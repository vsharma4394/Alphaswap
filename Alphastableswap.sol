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
 * @dev Inherits ERC20 for LP tokens. Uses Chainlink Oracles to securely fetch 
 * true market prices and trigger defensive mathematical regimes (circuit breakers).
 */
contract AlphaStableSwap is ERC20, ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    // --- State Variables ---

    IERC20 public immutable token0;
    IERC20 public immutable token1;

    // Chainlink Price Feeds for true market state detection
    AggregatorV3Interface public priceFeed0;
    AggregatorV3Interface public priceFeed1;

    // Internal reserves (balances tracked by the contract, isolated from direct transfers)
    uint256 public reserve0;
    uint256 public reserve1;

    // AMM Protocol Fees
    uint256 public swapFee = 3e15;       // 0.3% default fee (in 1e18 precision)
    uint256 public adminFee = 5e17;      // 50% of the swap fee goes to protocol
    
    // Max limits to prevent admin abuse (Rug-pull protection)
    uint256 public constant MAX_SWAP_FEE = 1e16; // Maximum 1% swap fee
    uint256 public constant MAX_ADMIN_FEE = 1e18; // Maximum 100% of swap fee goes to admin

    // Pending fees available for the admin to claim
    uint256 public adminBalance0;
    uint256 public adminBalance1;

    // --- Mathematical Constants & Regime Parameters ---
    
    uint256 constant N_COINS = 2;
    uint256 constant PRECISION = 1e18;
    uint256 constant MAX_ITERATIONS = 255;
    uint256 constant MINIMUM_LIQUIDITY = 10**3; // Prevents the first-depositor inflation attack
    uint256 constant ORACLE_TIMEOUT = 1 hours;  // Max age for oracle data before reverting

    // Regime I: Stable Market (Low Amplification, Soft Brake)
    uint256 constant A_REGIME_1 = 100;
    uint256 constant ALPHA_REGIME_1 = 2.5e18; 

    // Regime II: Mild De-peg (Mid Amplification, Harder Brake)
    uint256 constant A_REGIME_2 = 500;
    uint256 constant ALPHA_REGIME_2 = 4.5e18; 

    // Regime III: Severe Crash (High Amplification, Full Circuit Breaker)
    uint256 constant A_REGIME_3 = 1000;
    uint256 constant ALPHA_REGIME_3 = 6.5e18;

    // --- Events ---
    event TokenSwap(address indexed buyer, uint256 tokensSold, uint256 tokensBought, bool isToken0);
    event AddLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpMinted);
    event RemoveLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpBurned);
    event FeesUpdated(uint256 newSwapFee, uint256 newAdminFee);
    event AdminFeesCollected(uint256 amount0, uint256 amount1);

    // --- Modifiers ---
    
    /**
     * @dev Prevents pending transactions from executing after a certain time, 
     * protecting users from miners holding their transaction for favorable MEV execution.
     */
    modifier ensure(uint256 deadline) {
        require(deadline >= block.timestamp, "AlphaSwap: EXPIRED_DEADLINE");
        _;
    }

    /**
     * @notice Initializes the AMM pool with the two tokens and their respective Chainlink Oracles.
     * @param _token0 Address of the first ERC20 token
     * @param _token1 Address of the second ERC20 token
     * @param _priceFeed0 Chainlink Data Feed for token0 (e.g., USDC/USD)
     * @param _priceFeed1 Chainlink Data Feed for token1 (e.g., USDT/USD)
     */
    constructor(
        address _token0, 
        address _token1,
        address _priceFeed0,
        address _priceFeed1
    ) ERC20("AlphaSwap LP", "ALPHA-LP") {
        require(_token0 != address(0) && _token1 != address(0), "Invalid tokens");
        require(_priceFeed0 != address(0) && _priceFeed1 != address(0), "Invalid oracles");
        
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
        priceFeed0 = AggregatorV3Interface(_priceFeed0);
        priceFeed1 = AggregatorV3Interface(_priceFeed1);
    }

    /* ==============================================================================
       ORACLE & REGIME LOGIC: Secure Market State Detection
       ============================================================================== */

    /**
     * @notice Fetches the latest prices from Chainlink, checks for freshness, and calculates the deviation.
     * @dev Reverts if the oracle is broken, stale, or returns negative values.
     * @return ratio The price ratio normalized to 1e18 (always >= 1.0)
     */
    function getOracleMarketDeviation() public view returns (uint256) {
        // Fetch Token 0 Price
        (uint80 roundId0, int256 price0, , uint256 updatedAt0, uint80 answeredInRound0) = priceFeed0.latestRoundData();
        require(price0 > 0, "AlphaSwap: Oracle 0 invalid price");
        require(answeredInRound0 >= roundId0, "AlphaSwap: Oracle 0 stale round");
        require(block.timestamp - updatedAt0 < ORACLE_TIMEOUT, "AlphaSwap: Oracle 0 timeout");

        // Fetch Token 1 Price
        (uint80 roundId1, int256 price1, , uint256 updatedAt1, uint80 answeredInRound1) = priceFeed1.latestRoundData();
        require(price1 > 0, "AlphaSwap: Oracle 1 invalid price");
        require(answeredInRound1 >= roundId1, "AlphaSwap: Oracle 1 stale round");
        require(block.timestamp - updatedAt1 < ORACLE_TIMEOUT, "AlphaSwap: Oracle 1 timeout");

        uint256 p0 = uint256(price0);
        uint256 p1 = uint256(price1);

        // Calculate absolute deviation ratio (e.g., 1.05e18 means a 5% de-peg)
        // We always put the larger number on top to ensure ratio is >= 1.0
        return p0 > p1 ? (p0 * PRECISION) / p1 : (p1 * PRECISION) / p0;
    }

    /**
     * @notice Determines the strict mathematical regime based on the ORACLE De-peg.
     * @dev This protects against flash-loan manipulation because it relies on the global market price,
     * not the easily-manipulable internal balances of the smart contract.
     * @return A The Amplification coefficient
     * @return alpha The fractional weight (in UD60x18 format) applied to the product invariant
     */
    function getRegimeParameters() public view returns (uint256 A, UD60x18 alpha) {
        if (reserve0 == 0 || reserve1 == 0) return (A_REGIME_3, ud(ALPHA_REGIME_3));

        uint256 ratio = getOracleMarketDeviation();
        
        if (ratio < 1.1e18) {
            // < 10% deviation: Normal market conditions
            return (A_REGIME_1, ud(ALPHA_REGIME_1));
        } else if (ratio >= 1.1e18 && ratio < 1.3e18) {
            // 10% - 30% deviation: Imbalance detected, steepen the mathematical curve
            return (A_REGIME_2, ud(ALPHA_REGIME_2));
        } else {
            // > 30% deviation: Severe crash, trigger Circuit Breaker to stop bleeding
            return (A_REGIME_3, ud(ALPHA_REGIME_3)); 
        }
    }

    /* ==============================================================================
       MATHEMATICAL CORE: Generalized Power-Law Invariant (D) & Pricing (y)
       ============================================================================== */

    /**
     * @notice Computes generalized invariant D (Pool Depth) using advanced Newton-Raphson approximation.
     * @param x Current balance of token0
     * @param y Current balance of token1
     * @return D The total value parameter of the pool
     */
    function get_D(uint256 x, uint256 y) public view returns (uint256) {
        if (x == 0 && y == 0) return 0;
        
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

        // Iterative approximation loop
        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 D_P = D;
            UD60x18 uD = ud(D);

            UD60x18 fraction = pow(uD, d_exponent).div(denom);
            uint256 fraction_uint = fraction.unwrap();
            
            // Newton step computation balancing integer math for EVM
            uint256 num = (Ann * S) + (fraction_uint * (d_exponent.unwrap() / PRECISION));
            uint256 den = (Ann - 1) + ((fraction_uint * ((d_exponent.unwrap() / PRECISION) + 1)) / D);
            
            D = num / den;

            // Strict convergence logic: Break when D stabilizes
            if (D > D_P) {
                if (D - D_P <= 1) break;
            } else {
                if (D_P - D <= 1) break;
            }
        }
        return D;
    }

    /**
     * @notice Resolves the new required token balance `y` given a shifted balance `x` and depth `D`.
     * @param x The new balance of the input token
     * @param D The constant pool depth invariant
     * @return y The expected balance of the output token
     */
    function get_y(uint256 x, uint256 D) public view returns (uint256) {
        require(x > 0, "AlphaSwap: Zero x");
        
        (uint256 A, UD60x18 alpha) = getRegimeParameters(); 
        
        uint256 Ann = A * N_COINS * N_COINS;
        UD60x18 ux = ud(x);
        UD60x18 uD = ud(D);
        UD60x18 un2 = ud(N_COINS * N_COINS);

        UD60x18 d_exponent = alpha.mul(ud(2e18)).add(ud(1e18)); // 2*alpha + 1
        
        // num_constant = D^(2a+1) / (n^2 * x^alpha)
        UD60x18 num_constant = pow(uD, d_exponent).div(un2.mul(pow(ux, alpha)));

        uint256 y = D; // Initial guess

        // Iterative approximation loop
        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 y_prev = y;
            UD60x18 uy = ud(y);

            UD60x18 fraction = num_constant.div(pow(uy, alpha));
            uint256 fraction_uint = fraction.unwrap();

            // Newton step for y calculation
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

    /**
     * @notice Executes a token swap utilizing the dynamic alpha mathematical braking curve.
     * @param amountIn Amount of tokens being sold
     * @param isToken0 True if selling token0, false if selling token1
     * @param minAmountOut The minimum acceptable tokens bought (Slippage protection)
     * @param deadline Unix timestamp after which the trade is invalid
     * @return amountOut The total tokens sent to the buyer
     */
    function swap(
        uint256 amountIn, 
        bool isToken0, 
        uint256 minAmountOut,
        uint256 deadline
    ) external nonReentrant ensure(deadline) returns (uint256 amountOut) {
        require(amountIn > 0, "AlphaSwap: Insufficient input");

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
        
        // Calculate swap output and take fees
        uint256 rawAmountOut = y - y_new;
        uint256 fee = (rawAmountOut * swapFee) / PRECISION;
        uint256 adminFeeAlloc = (fee * adminFee) / PRECISION;
        amountOut = rawAmountOut - fee;

        require(amountOut >= minAmountOut, "AlphaSwap: Slippage tolerance exceeded");

        // Update state and execute transfers
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

    /**
     * @notice Allows liquidity providers to supply tokens to the AMM pool.
     * @param amount0 Amount of token0 provided
     * @param amount1 Amount of token1 provided
     * @param minLPMinted Minimum acceptable LP tokens received
     * @param deadline Unix timestamp after which the provision is invalid
     * @return lpMinted The amount of ERC20 LP tokens given to the provider
     */
    function addLiquidity(
        uint256 amount0, 
        uint256 amount1, 
        uint256 minLPMinted,
        uint256 deadline
    ) external nonReentrant ensure(deadline) returns (uint256 lpMinted) {
        require(amount0 > 0 || amount1 > 0, "AlphaSwap: Zero amounts");

        uint256 D0 = get_D(reserve0, reserve1);
        uint256 _totalSupply = totalSupply();
        
        token0.safeTransferFrom(msg.sender, address(this), amount0);
        token1.safeTransferFrom(msg.sender, address(this), amount1);
        
        reserve0 += amount0;
        reserve1 += amount1;

        uint256 D1 = get_D(reserve0, reserve1);
        require(D1 > D0, "AlphaSwap: Invariant must increase");

        if (_totalSupply == 0) {
            lpMinted = D1; 
            // Send first 1000 LP tokens to zero address to permanently lock the ratio 
            // and prevent the initial depositor inflation attack.
            _mint(address(0), MINIMUM_LIQUIDITY);
            lpMinted -= MINIMUM_LIQUIDITY;
        } else {
            // Proportional LP token minting based on invariant growth
            lpMinted = ((D1 - D0) * _totalSupply) / D0; 
        }

        require(lpMinted >= minLPMinted, "AlphaSwap: Slippage on mint");
        _mint(msg.sender, lpMinted);

        emit AddLiquidity(msg.sender, amount0, amount1, lpMinted);
    }

    /**
     * @notice Allows LPs to burn their LP tokens and withdraw underlying assets.
     * @param lpAmount The number of LP tokens to burn
     * @param minAmount0 Minimum token0 required to be withdrawn
     * @param minAmount1 Minimum token1 required to be withdrawn
     * @param deadline Unix timestamp after which the withdrawal is invalid
     */
    function removeLiquidity(
        uint256 lpAmount, 
        uint256 minAmount0, 
        uint256 minAmount1,
        uint256 deadline
    ) external nonReentrant ensure(deadline) {
        uint256 totalLp = totalSupply();
        require(totalLp > 0 && lpAmount > 0, "AlphaSwap: Invalid LP amount");

        // Calculate withdrawal amounts proportionally
        uint256 amount0 = (lpAmount * reserve0) / totalLp;
        uint256 amount1 = (lpAmount * reserve1) / totalLp;

        require(amount0 >= minAmount0 && amount1 >= minAmount1, "AlphaSwap: Slippage on burn");

        reserve0 -= amount0;
        reserve1 -= amount1;

        _burn(msg.sender, lpAmount);

        token0.safeTransfer(msg.sender, amount0);
        token1.safeTransfer(msg.sender, amount1);

        emit RemoveLiquidity(msg.sender, amount0, amount1, lpAmount);
    }

    /* ==============================================================================
       ADMIN FUNCTIONS
       ============================================================================== */

    /**
     * @notice Updates the protocol fee settings.
     * @param newSwapFee The new swap fee (e.g., 3e15 for 0.3%)
     * @param newAdminFee The portion of the swap fee reserved for the protocol
     */
    function setFees(uint256 newSwapFee, uint256 newAdminFee) external onlyOwner {
        require(newSwapFee <= MAX_SWAP_FEE, "AlphaSwap: Swap fee exceeds max");
        require(newAdminFee <= MAX_ADMIN_FEE, "AlphaSwap: Admin fee exceeds max");
        swapFee = newSwapFee;
        adminFee = newAdminFee;
        emit FeesUpdated(newSwapFee, newAdminFee);
    }

    /**
     * @notice Admin function to collect protocol fees generated from trades.
     */
    function collectAdminFees() external onlyOwner {
        uint256 a0 = adminBalance0;
        uint256 a1 = adminBalance1;

        adminBalance0 = 0;
        adminBalance1 = 0;

        if(a0 > 0) token0.safeTransfer(owner(), a0);
        if(a1 > 0) token1.safeTransfer(owner(), a1);

        emit AdminFeesCollected(a0, a1);
    }

    /**
     * @notice Updates Oracle Addresses in case an oracle is deprecated by Chainlink.
     */
    function setOracles(address _priceFeed0, address _priceFeed1) external onlyOwner {
        require(_priceFeed0 != address(0) && _priceFeed1 != address(0), "AlphaSwap: Invalid oracle");
        priceFeed0 = AggregatorV3Interface(_priceFeed0);
        priceFeed1 = AggregatorV3Interface(_priceFeed1);
    }
}