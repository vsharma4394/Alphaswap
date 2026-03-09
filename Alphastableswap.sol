// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// Chainlink Oracle Interface
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

// PRBMath for Advanced Fractional Exponents (Floating Point Math)
import { UD60x18, ud, exp, ln, pow } from "@prb/math/src/UD60x18.sol";

/**
 * @title AlphaStableSwap - Oracle-Driven Generalized Power-Law AMM
 * @author Varun Sharma (IIT Roorkee - MA500A-P)
 * @notice Production-grade implementation of the Alpha-variant StableSwap invariant.
 * @dev Uses Chainlink Oracles to securely fetch true market prices and trigger defensive regimes.
 */
contract AlphaStableSwap is ERC20, ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable token0;
    IERC20 public immutable token1;

    // Chainlink Price Feeds
    AggregatorV3Interface public priceFeed0;
    AggregatorV3Interface public priceFeed1;

    uint256 public reserve0;
    uint256 public reserve1;

    // AMM Protocol Fees
    uint256 public swapFee = 3e15;       // 0.3% default fee (in 1e18 precision)
    uint256 public adminFee = 5e17;      // 50% of swap fee goes to protocol
    uint256 public adminBalance0;
    uint256 public adminBalance1;

    // Constants & Regime Parameters
    uint256 constant N_COINS = 2;
    uint256 constant PRECISION = 1e18;
    uint256 constant MAX_ITERATIONS = 255;

    // Regimes
    uint256 constant A_REGIME_1 = 100;
    uint256 constant ALPHA_REGIME_1 = 2.5e18; 

    uint256 constant A_REGIME_2 = 500;
    uint256 constant ALPHA_REGIME_2 = 4.5e18; 

    uint256 constant A_REGIME_3 = 1000;
    uint256 constant ALPHA_REGIME_3 = 6.5e18;

    // Events
    event TokenSwap(address indexed buyer, uint256 tokensSold, uint256 tokensBought, bool isToken0);
    event AddLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpMinted);
    event RemoveLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpBurned);
    event RegimeChanged(uint256 newA, uint256 newAlpha, uint256 currentDeviation);

    constructor(
        address _token0, 
        address _token1,
        address _priceFeed0,
        address _priceFeed1
    ) ERC20("AlphaSwap LP", "ALPHA-LP") {
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
        priceFeed0 = AggregatorV3Interface(_priceFeed0);
        priceFeed1 = AggregatorV3Interface(_priceFeed1);
    }

    /* ==============================================================================
       ORACLE & REGIME LOGIC: Secure Market State Detection
       ============================================================================== */

    /**
     * @notice Fetches the latest prices from Chainlink and calculates the deviation ratio
     * @return ratio The price ratio normalized to 1e18 (always >= 1.0)
     */
    function getOracleMarketDeviation() public view returns (uint256) {
        (, int256 price0, , , ) = priceFeed0.latestRoundData();
        (, int256 price1, , , ) = priceFeed1.latestRoundData();
        
        require(price0 > 0 && price1 > 0, "Invalid oracle price data");

        uint256 p0 = uint256(price0);
        uint256 p1 = uint256(price1);

        // Calculate absolute deviation ratio (e.g., 1.05e18 means a 5% de-peg)
        return p0 > p1 ? (p0 * PRECISION) / p1 : (p1 * PRECISION) / p0;
    }

    /**
     * @notice Determines the strict regime constraints based on the ORACLE De-peg
     * @dev This protects against flash-loan manipulation of internal pool balances
     */
    function getRegimeParameters() public view returns (uint256 A, UD60x18 alpha) {
        if (reserve0 == 0 || reserve1 == 0) return (A_REGIME_3, ud(ALPHA_REGIME_3));

        uint256 ratio = getOracleMarketDeviation();
        
        if (ratio < 1.1e18) {
            // < 10% deviation: Normal conditions
            return (A_REGIME_1, ud(ALPHA_REGIME_1));
        } else if (ratio >= 1.1e18 && ratio < 1.3e18) {
            // 10% - 30% deviation: Imbalance detected, steepen curve
            return (A_REGIME_2, ud(ALPHA_REGIME_2));
        } else {
            // > 30% deviation: Severe crash, trigger Circuit Breaker
            return (A_REGIME_3, ud(ALPHA_REGIME_3)); 
        }
    }

    /* ==============================================================================
       MATHEMATICAL CORE: Generalized Power-Law Invariant (D) & Pricing (y)
       ============================================================================== */

    /**
     * @notice Computes generalized invariant D using advanced Newton-Raphson
     * @dev Solves for D in: A * n^2 * (x + y) + D = A * D * n^2 + (D^(2a+1)) / (n^2 * (xy)^a)
     */
    function get_D(uint256 x, uint256 y) public view returns (uint256) {
        if (x == 0 && y == 0) return 0;
        
        // A and Alpha are now pulled securely from the oracle state
        (uint256 A, UD60x18 alpha) = getRegimeParameters();
        uint256 S = x + y;
        uint256 D = S; // Initial guess
        uint256 Ann = A * N_COINS * N_COINS;

        UD60x18 ux = ud(x);
        UD60x18 uy = ud(y);
        UD60x18 un2 = ud(N_COINS * N_COINS);
        
        // Denominator: n^2 * (xy)^alpha
        UD60x18 denom = un2.mul(pow(ux.mul(uy), alpha));
        UD60x18 d_exponent = alpha.mul(ud(2e18)).add(ud(1e18)); // 2*alpha + 1

        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 D_P = D;
            UD60x18 uD = ud(D);

            UD60x18 fraction = pow(uD, d_exponent).div(denom);
            uint256 fraction_uint = fraction.unwrap();
            
            // Newton step computation balancing integer math for EVM
            uint256 num = (Ann * S) + (fraction_uint * (d_exponent.unwrap() / PRECISION));
            uint256 den = (Ann - 1) + ((fraction_uint * ((d_exponent.unwrap() / PRECISION) + 1)) / D);
            
            D = num / den;

            // Strict convergence logic
            if (D > D_P) {
                if (D - D_P <= 1) break;
            } else {
                if (D_P - D <= 1) break;
            }
        }
        return D;
    }

    /**
     * @notice Resolves new token balance y given shifted balance x
     */
    function get_y(uint256 x, uint256 D) public view returns (uint256) {
        require(x > 0, "Zero x");
        
        // Oracle-driven regime
        (uint256 A, UD60x18 alpha) = getRegimeParameters(); 
        
        uint256 Ann = A * N_COINS * N_COINS;
        UD60x18 ux = ud(x);
        UD60x18 uD = ud(D);
        UD60x18 un2 = ud(N_COINS * N_COINS);

        UD60x18 d_exponent = alpha.mul(ud(2e18)).add(ud(1e18));
        UD60x18 num_constant = pow(uD, d_exponent).div(un2.mul(pow(ux, alpha)));

        uint256 y = D; 

        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 y_prev = y;
            UD60x18 uy = ud(y);

            UD60x18 fraction = num_constant.div(pow(uy, alpha));
            uint256 fraction_uint = fraction.unwrap();

            uint256 y_num = (y * y) + fraction_uint;
            uint256 y_den = (y * 2) + (x * Ann) + (D * Ann) - D + (fraction_uint / y); 

            y = y_num / y_den;

            if (y > y_prev) {
                if (y - y_prev <= 1) break;
            } else {
                if (y_prev - y <= 1) break;
            }
        }
        return y;
    }

    /* ==============================================================================
       PROTOCOL OPERATIONS: Swaps, Add/Remove Liquidity
       ============================================================================== */

    function swap(uint256 amountIn, bool isToken0, uint256 minAmountOut) external nonReentrant returns (uint256 amountOut) {
        require(amountIn > 0, "Insufficient input");

        uint256 x;
        uint256 y;
        
        if (isToken0) {
            x = reserve0 + amountIn;
            y = reserve1;
        } else {
            x = reserve1 + amountIn;
            y = reserve0;
        }

        uint256 D = get_D(reserve0, reserve1);
        uint256 y_new = get_y(x, D);
        
        uint256 rawAmountOut = y - y_new;
        uint256 fee = (rawAmountOut * swapFee) / PRECISION;
        uint256 adminFeeAlloc = (fee * adminFee) / PRECISION;
        amountOut = rawAmountOut - fee;

        require(amountOut >= minAmountOut, "Slippage tolerance exceeded");

        if (isToken0) {
            reserve0 += amountIn;
            reserve1 -= rawAmountOut;
            adminBalance1 += adminFeeAlloc;
            token0.safeTransferFrom(msg.sender, address(this), amountIn);
            token1.safeTransfer(msg.sender, amountOut);
        } else {
            reserve1 += amountIn;
            reserve0 -= rawAmountOut;
            adminBalance0 += adminFeeAlloc;
            token1.safeTransferFrom(msg.sender, address(this), amountIn);
            token0.safeTransfer(msg.sender, amountOut);
        }

        emit TokenSwap(msg.sender, amountIn, amountOut, isToken0);
    }

    function addLiquidity(uint256 amount0, uint256 amount1, uint256 minLPMinted) external nonReentrant returns (uint256 lpMinted) {
        require(amount0 > 0 || amount1 > 0, "Zero amounts");

        uint256 D0 = get_D(reserve0, reserve1);
        
        token0.safeTransferFrom(msg.sender, address(this), amount0);
        token1.safeTransferFrom(msg.sender, address(this), amount1);
        
        reserve0 += amount0;
        reserve1 += amount1;

        uint256 D1 = get_D(reserve0, reserve1);
        require(D1 > D0, "D must increase");

        if (totalSupply() == 0) {
            lpMinted = D1; 
        } else {
            lpMinted = ((D1 - D0) * totalSupply()) / D0; 
        }

        require(lpMinted >= minLPMinted, "Slippage on mint");
        _mint(msg.sender, lpMinted);

        emit AddLiquidity(msg.sender, amount0, amount1, lpMinted);
    }

    function removeLiquidity(uint256 lpAmount, uint256 minAmount0, uint256 minAmount1) external nonReentrant {
        uint256 totalLp = totalSupply();
        require(totalLp > 0 && lpAmount > 0, "Invalid LP amount");

        uint256 amount0 = (lpAmount * reserve0) / totalLp;
        uint256 amount1 = (lpAmount * reserve1) / totalLp;

        require(amount0 >= minAmount0 && amount1 >= minAmount1, "Slippage on burn");

        reserve0 -= amount0;
        reserve1 -= amount1;

        _burn(msg.sender, lpAmount);

        token0.safeTransfer(msg.sender, amount0);
        token1.safeTransfer(msg.sender, amount1);

        emit RemoveLiquidity(msg.sender, amount0, amount1, lpAmount);
    }

    // Update Oracle Addresses (In case an oracle is deprecated by Chainlink)
    function setOracles(address _priceFeed0, address _priceFeed1) external onlyOwner {
        priceFeed0 = AggregatorV3Interface(_priceFeed0);
        priceFeed1 = AggregatorV3Interface(_priceFeed1);
    }
}