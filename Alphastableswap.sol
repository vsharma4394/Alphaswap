// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

// PRBMath for Advanced Fractional Exponents (Floating Point Math)
import { UD60x18, ud, pow } from "@prb/math/src/UD60x18.sol";

/**
 * @title AlphaSwapPool - Pure Power-Law AMM
 * @author Varun Sharma (IIT Roorkee - MA500A-P)
 * @notice Production-grade implementation of the Alpha-variant StableSwap invariant.
 * @dev This contract represents a SINGLE regime pool. A and Alpha are immutable.
 * The mathematical invariant alone provides the defensive slippage against arbitrage.
 */
contract AlphaSwapPool is ERC20, ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    // --- State Variables ---

    IERC20 public immutable token0;
    IERC20 public immutable token1;

    // The core mathematical parameters (Immutable per pool deployment)
    uint256 public immutable A;         // Amplification coefficient
    uint256 public immutable alpha;     // The power-law exponent (scaled by 1e18)

    // Internal reserves
    uint256 public reserve0;
    uint256 public reserve1;

    // AMM Protocol Fees
    uint256 public swapFee = 3e15;       // 0.3% default fee (in 1e18 precision)
    uint256 public adminFee = 5e17;      // 50% of the swap fee goes to protocol
    
    uint256 public constant MAX_SWAP_FEE = 1e16; // Maximum 1% swap fee
    uint256 public constant MAX_ADMIN_FEE = 1e18; // Maximum 100% of swap fee

    uint256 public adminBalance0;
    uint256 public adminBalance1;

    // --- Mathematical Constants ---
    uint256 constant N_COINS = 2;
    uint256 constant PRECISION = 1e18;
    uint256 constant MAX_ITERATIONS = 255;
    uint256 constant MINIMUM_LIQUIDITY = 10**3;

    // --- Events ---
    event TokenSwap(address indexed buyer, uint256 tokensSold, uint256 tokensBought, bool isToken0);
    event AddLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpMinted);
    event RemoveLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpBurned);

    modifier ensure(uint256 deadline) {
        require(deadline >= block.timestamp, "AlphaSwap: EXPIRED_DEADLINE");
        _;
    }

    /**
     * @notice Initializes the AMM pool with fixed mathematical parameters.
     * @param _token0 Address of the first ERC20 token
     * @param _token1 Address of the second ERC20 token
     * @param _A The fixed Amplification coefficient for this specific pool
     * @param _alpha The fixed fractional weight (e.g., 2.5e18, 4.5e18, or 6.5e18)
     */
    constructor(
        address _token0, 
        address _token1,
        uint256 _A,
        uint256 _alpha
    ) ERC20("AlphaSwap LP", "ALPHA-LP") {
        require(_token0 != address(0) && _token1 != address(0), "Invalid tokens");
        require(_A > 0 && _alpha > 0, "Invalid invariant parameters");
        
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
        A = _A;
        alpha = _alpha;
    }

    /* ==============================================================================
       MATHEMATICAL CORE: Generalized Power-Law Invariant (D) & Pricing (y)
       ============================================================================== */

    /**
     * @notice Computes generalized invariant D (Pool Depth) using Newton-Raphson approximation.
     */
    function get_D(uint256 x, uint256 y) public view returns (uint256) {
        if (x == 0 && y == 0) return 0;
        
        uint256 S = x + y;
        uint256 D = S; // Initial guess
        uint256 Ann = A * N_COINS * N_COINS;

        UD60x18 ux = ud(x);
        UD60x18 uy = ud(y);
        UD60x18 un2 = ud(N_COINS * N_COINS);
        UD60x18 uAlpha = ud(alpha);
        
        // Denominator: n^2 * (xy)^alpha
        UD60x18 denom = un2.mul(pow(ux.mul(uy), uAlpha));
        UD60x18 d_exponent = uAlpha.mul(ud(2e18)).add(ud(1e18)); // 2*alpha + 1

        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 D_P = D;
            UD60x18 uD = ud(D);

            UD60x18 fraction = pow(uD, d_exponent).div(denom);
            uint256 fraction_uint = fraction.unwrap();
            
            uint256 num = (Ann * S) + (fraction_uint * (d_exponent.unwrap() / PRECISION));
            uint256 den = (Ann - 1) + ((fraction_uint * ((d_exponent.unwrap() / PRECISION) + 1)) / D);
            
            D = num / den;

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
     */
    function get_y(uint256 x, uint256 D) public view returns (uint256) {
        require(x > 0, "AlphaSwap: Zero x");
        
        uint256 Ann = A * N_COINS * N_COINS;
        UD60x18 ux = ud(x);
        UD60x18 uD = ud(D);
        UD60x18 un2 = ud(N_COINS * N_COINS);
        UD60x18 uAlpha = ud(alpha);

        UD60x18 d_exponent = uAlpha.mul(ud(2e18)).add(ud(1e18)); // 2*alpha + 1
        
        // num_constant = D^(2a+1) / (n^2 * x^alpha)
        UD60x18 num_constant = pow(uD, d_exponent).div(un2.mul(pow(ux, uAlpha)));

        uint256 y = D; 

        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 y_prev = y;
            UD60x18 uy = ud(y);

            UD60x18 fraction = num_constant.div(pow(uy, uAlpha));
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
        
        uint256 rawAmountOut = y - y_new;
        uint256 fee = (rawAmountOut * swapFee) / PRECISION;
        uint256 adminFeeAlloc = (fee * adminFee) / PRECISION;
        amountOut = rawAmountOut - fee;

        require(amountOut >= minAmountOut, "AlphaSwap: Slippage tolerance exceeded");

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
            _mint(address(0), MINIMUM_LIQUIDITY);
            lpMinted -= MINIMUM_LIQUIDITY;
        } else {
            lpMinted = ((D1 - D0) * _totalSupply) / D0; 
        }

        require(lpMinted >= minLPMinted, "AlphaSwap: Slippage on mint");
        _mint(msg.sender, lpMinted);

        emit AddLiquidity(msg.sender, amount0, amount1, lpMinted);
    }

    function removeLiquidity(
        uint256 lpAmount, 
        uint256 minAmount0, 
        uint256 minAmount1,
        uint256 deadline
    ) external nonReentrant ensure(deadline) {
        uint256 totalLp = totalSupply();
        require(totalLp > 0 && lpAmount > 0, "AlphaSwap: Invalid LP amount");

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

    function setFees(uint256 newSwapFee, uint256 newAdminFee) external onlyOwner {
        require(newSwapFee <= MAX_SWAP_FEE, "AlphaSwap: Swap fee exceeds max");
        require(newAdminFee <= MAX_ADMIN_FEE, "AlphaSwap: Admin fee exceeds max");
        swapFee = newSwapFee;
        adminFee = newAdminFee;
        emit FeesUpdated(newSwapFee, newAdminFee);
    }

    function collectAdminFees() external onlyOwner {
        uint256 a0 = adminBalance0;
        uint256 a1 = adminBalance1;

        adminBalance0 = 0;
        adminBalance1 = 0;

        if(a0 > 0) token0.safeTransfer(owner(), a0);
        if(a1 > 0) token1.safeTransfer(owner(), a1);

        emit AdminFeesCollected(a0, a1);
    }
}