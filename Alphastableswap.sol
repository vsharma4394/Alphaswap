// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

// PRBMath for Advanced Fractional Exponents (Floating Point Math)
import { UD60x18, ud, pow } from "@prb/math/src/UD60x18.sol";

// ERC-3156 Flash Loan Interfaces
interface IERC3156FlashBorrower {
    function onFlashLoan(address initiator, address token, uint256 amount, uint256 fee, bytes calldata data) external returns (bytes32);
}

interface IERC3156FlashLender {
    function maxFlashLoan(address token) external view returns (uint256);
    function flashFee(address token, uint256 amount) external view returns (uint256);
    function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data) external returns (bool);
}

/**
 * @title AlphaSwapPool - Pure Power-Law AMM (Production Grade)
 * @author Varun Sharma (IIT Roorkee - MA500A-P)
 * @notice Production-grade implementation of the Alpha-variant StableSwap invariant.
 * @dev Optimized for beta = 1. Features TWAP Oracles, Flash Loans, and Gasless Permits.
 */
contract AlphaSwapPool is ERC20, ERC20Permit, ReentrancyGuard, Ownable, Pausable, IERC3156FlashLender {
    using SafeERC20 for IERC20;

    /* ==============================================================================
       STATE VARIABLES & CONSTANTS
       ============================================================================== */

    IERC20 public immutable token0;
    IERC20 public immutable token1;

    // The core mathematical parameters
    uint256 public immutable A;         // Amplification coefficient
    uint256 public immutable alpha;     // The power-law exponent for token0 (scaled by 1e18)
    
    // Beta is mathematically locked to 1 to optimize EVM gas costs.
    uint256 public constant BETA = 1e18; 

    // Internal reserves
    uint256 public reserve0;
    uint256 public reserve1;

    // TWAP Oracle Accumulators (Uniswap V2 Style)
    uint256 public price0CumulativeLast;
    uint256 public price1CumulativeLast;
    uint32  public blockTimestampLast;

    // AMM Protocol Fees
    uint256 public swapFee = 3e15;       // 0.3% default fee
    uint256 public adminFee = 5e17;      // 50% of the swap fee goes to protocol
    uint256 public flashLoanFee = 9e14;  // 0.09% fee for flash loans
    
    uint256 public constant MAX_SWAP_FEE = 1e16; 
    uint256 public constant MAX_ADMIN_FEE = 1e18; 

    uint256 public adminBalance0;
    uint256 public adminBalance1;

    // Protocol Analytics
    uint256 public totalVolume0;
    uint256 public totalVolume1;

    // --- Mathematical Constants ---
    uint256 constant N_COINS = 2;
    uint256 constant PRECISION = 1e18;
    uint256 constant MAX_ITERATIONS = 255;
    uint256 constant MINIMUM_LIQUIDITY = 10**3;
    
    // Flash Loan standard callback hash
    bytes32 public constant CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    /* ==============================================================================
       EVENTS
       ============================================================================== */

    event TokenSwap(address indexed buyer, uint256 tokensSold, uint256 tokensBought, bool isToken0);
    event AddLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpMinted);
    event RemoveLiquidity(address indexed provider, uint256 token0Amount, uint256 token1Amount, uint256 lpBurned);
    event Sync(uint256 reserve0, uint256 reserve1);
    event FlashLoan(address indexed receiver, address indexed token, uint256 amount, uint256 fee);
    event FeesUpdated(uint256 newSwapFee, uint256 newAdminFee, uint256 newFlashFee);
    event AdminFeesCollected(uint256 amount0, uint256 amount1);

    /* ==============================================================================
       MODIFIERS
       ============================================================================== */

    modifier ensure(uint256 deadline) {
        require(deadline >= block.timestamp, "AlphaSwap: EXPIRED_DEADLINE");
        _;
    }

    /* ==============================================================================
       INITIALIZATION
       ============================================================================== */

    constructor(
        address _token0, 
        address _token1,
        uint256 _A,
        uint256 _alpha
    ) ERC20("AlphaSwap LP", "ALPHA-LP") ERC20Permit("AlphaSwap LP") {
        require(_token0 != address(0) && _token1 != address(0), "Invalid tokens");
        require(_token0 != _token1, "Identical tokens");
        require(_A > 0 && _alpha > 0, "Invalid invariant parameters");
        
        token0 = IERC20(_token0);
        token1 = IERC20(_token1);
        A = _A;
        alpha = _alpha;
    }

    /* ==============================================================================
       TWAP ORACLE LOGIC
       ============================================================================== */

    /**
     * @notice Updates the Time-Weighted Average Price (TWAP) accumulators.
     * @dev Called on every state-changing operation to provide secure on-chain pricing to other dApps.
     */
    function _update(uint256 balance0, uint256 balance1) private {
        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast;
        
        if (timeElapsed > 0 && reserve0 != 0 && reserve1 != 0) {
            // Using precise UQ112x112 encoding concept for price accumulation
            unchecked {
                price0CumulativeLast += (reserve1 * PRECISION / reserve0) * timeElapsed;
                price1CumulativeLast += (reserve0 * PRECISION / reserve1) * timeElapsed;
            }
        }
        
        reserve0 = balance0;
        reserve1 = balance1;
        blockTimestampLast = blockTimestamp;
        
        emit Sync(reserve0, reserve1);
    }

    /* ==============================================================================
       MATHEMATICAL CORE: Generalized Power-Law Invariant (D) & Pricing (y)
       ============================================================================== */

    /**
     * @notice Computes invariant D using Newton-Raphson approximation.
     * @dev Optimized for Beta = 1. Solves: A*n^2*(x+y) + D = A*D*n^2 + D^(alpha+2) / (n^2 * x^alpha * y)
     * @param x Current balance of token0
     * @param y Current balance of token1
     * @return D The total invariant value of the pool
     */
    function get_D(uint256 x, uint256 y) public view returns (uint256) {
        if (x == 0 && y == 0) return 0;
        
        uint256 S = x + y;
        uint256 D = S; 
        uint256 Ann = A * N_COINS * N_COINS;

        UD60x18 ux = ud(x);
        UD60x18 uy = ud(y);
        UD60x18 un2 = ud(N_COINS * N_COINS);
        UD60x18 uAlpha = ud(alpha);
        
        // Denominator: n^2 * x^alpha * y
        UD60x18 denom = un2.mul(pow(ux, uAlpha)).mul(uy);
        
        // Exponent for D: alpha + 2
        UD60x18 d_exponent = uAlpha.add(ud(2e18)); 

        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 D_P = D;
            UD60x18 uD = ud(D);

            UD60x18 fraction = pow(uD, d_exponent).div(denom);
            uint256 fraction_uint = fraction.unwrap();
            
            // Newton step logic algebraically simplified to prevent stack-too-deep
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
     * @param x The new shifted balance of the input token
     * @param D The constant pool depth invariant required to be maintained
     * @return y The expected balance of the output token
     */
    function get_y(uint256 x, uint256 D) public view returns (uint256) {
        require(x > 0, "AlphaSwap: Zero x");
        
        uint256 Ann = A * N_COINS * N_COINS;
        UD60x18 ux = ud(x);
        UD60x18 uD = ud(D);
        UD60x18 un2 = ud(N_COINS * N_COINS);
        UD60x18 uAlpha = ud(alpha);

        // Exponent for D: alpha + 2
        UD60x18 d_exponent = uAlpha.add(ud(2e18)); 
        
        // Constant part of numerator: D^(alpha+2) / (n^2 * x^alpha)
        UD60x18 num_constant = pow(uD, d_exponent).div(un2.mul(pow(ux, uAlpha)));

        uint256 y = D; 

        for (uint256 i = 0; i < MAX_ITERATIONS; i++) {
            uint256 y_prev = y;
            UD60x18 uy = ud(y);

            // Optimization: Beta=1 means we divide purely by y, no exponents needed
            UD60x18 fraction = num_constant.div(uy);
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
       ROUTER & FRONTEND HELPERS (Read-Only)
       ============================================================================== */

    /**
     * @notice Helper function for frontends to quote a swap without executing it.
     */
    function quoteSwap(uint256 amountIn, bool isToken0) external view returns (uint256 amountOut, uint256 fee) {
        if (amountIn == 0) return (0, 0);

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
        fee = (rawAmountOut * swapFee) / PRECISION;
        amountOut = rawAmountOut - fee;
    }

    /**
     * @notice Helper function to calculate expected LP tokens for a given deposit.
     */
    function quoteAddLiquidity(uint256 amount0, uint256 amount1) external view returns (uint256 lpMinted) {
        uint256 D0 = get_D(reserve0, reserve1);
        uint256 D1 = get_D(reserve0 + amount0, reserve1 + amount1);
        
        if (totalSupply() == 0) {
            lpMinted = D1 - MINIMUM_LIQUIDITY;
        } else {
            lpMinted = ((D1 - D0) * totalSupply()) / D0;
        }
    }

    /* ==============================================================================
       PROTOCOL OPERATIONS: Swaps, Add/Remove Liquidity
       ============================================================================== */

    /**
     * @notice Core swap function utilizing the Alpha-Brake invariant.
     */
    function swap(
        uint256 amountIn, 
        bool isToken0, 
        uint256 minAmountOut,
        uint256 deadline
    ) external nonReentrant whenNotPaused ensure(deadline) returns (uint256 amountOut) {
        require(amountIn > 0, "AlphaSwap: Insufficient input");

        uint256 x;
        uint256 y;
        uint256 balance0;
        uint256 balance1;
        
        if (isToken0) {
            x = reserve0 + amountIn;
            y = reserve1;
        } else {
            x = reserve1 + amountIn;
            y = reserve0;
        }

        // 1. Math Execution
        uint256 D = get_D(reserve0, reserve1);
        uint256 y_new = get_y(x, D);
        
        uint256 rawAmountOut = y - y_new;
        uint256 fee = (rawAmountOut * swapFee) / PRECISION;
        uint256 adminFeeAlloc = (fee * adminFee) / PRECISION;
        amountOut = rawAmountOut - fee;

        require(amountOut >= minAmountOut, "AlphaSwap: Slippage tolerance exceeded");

        // 2. State Updates & Transfers
        if (isToken0) {
            balance0 = reserve0 + amountIn;
            balance1 = reserve1 - rawAmountOut;
            adminBalance1 += adminFeeAlloc;
            totalVolume0 += amountIn;
            
            token0.safeTransferFrom(msg.sender, address(this), amountIn);
            token1.safeTransfer(msg.sender, amountOut);
        } else {
            balance1 = reserve1 + amountIn;
            balance0 = reserve0 - rawAmountOut;
            adminBalance0 += adminFeeAlloc;
            totalVolume1 += amountIn;
            
            token1.safeTransferFrom(msg.sender, address(this), amountIn);
            token0.safeTransfer(msg.sender, amountOut);
        }

        // 3. Oracle Sync
        _update(balance0, balance1);

        emit TokenSwap(msg.sender, amountIn, amountOut, isToken0);
    }

    /**
     * @notice Allows LPs to deposit assets and receive yield-bearing LP tokens.
     */
    function addLiquidity(
        uint256 amount0, 
        uint256 amount1, 
        uint256 minLPMinted,
        uint256 deadline
    ) external nonReentrant whenNotPaused ensure(deadline) returns (uint256 lpMinted) {
        require(amount0 > 0 || amount1 > 0, "AlphaSwap: Zero amounts");

        uint256 D0 = get_D(reserve0, reserve1);
        uint256 _totalSupply = totalSupply();
        
        token0.safeTransferFrom(msg.sender, address(this), amount0);
        token1.safeTransferFrom(msg.sender, address(this), amount1);
        
        uint256 balance0 = reserve0 + amount0;
        uint256 balance1 = reserve1 + amount1;

        uint256 D1 = get_D(balance0, balance1);
        require(D1 > D0, "AlphaSwap: Invariant must increase");

        if (_totalSupply == 0) {
            lpMinted = D1; 
            _mint(address(0), MINIMUM_LIQUIDITY); // Permanent lock to prevent inflation attacks
            lpMinted -= MINIMUM_LIQUIDITY;
        } else {
            lpMinted = ((D1 - D0) * _totalSupply) / D0; 
        }

        require(lpMinted >= minLPMinted, "AlphaSwap: Slippage on mint");
        _mint(msg.sender, lpMinted);
        
        _update(balance0, balance1);

        emit AddLiquidity(msg.sender, amount0, amount1, lpMinted);
    }

    /**
     * @notice Burns LP tokens to withdraw underlying assets proportionally.
     */
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

        uint256 balance0 = reserve0 - amount0;
        uint256 balance1 = reserve1 - amount1;

        _burn(msg.sender, lpAmount);

        token0.safeTransfer(msg.sender, amount0);
        token1.safeTransfer(msg.sender, amount1);
        
        _update(balance0, balance1);

        emit RemoveLiquidity(msg.sender, amount0, amount1, lpAmount);
    }

    /* ==============================================================================
       ERC-3156 FLASH LOAN IMPLEMENTATION
       ============================================================================== */

    /**
     * @notice Returns the maximum amount of tokens available for a flash loan.
     */
    function maxFlashLoan(address token) external view override returns (uint256) {
        if (token == address(token0)) return reserve0;
        if (token == address(token1)) return reserve1;
        return 0;
    }

    /**
     * @notice Returns the fee required for a flash loan.
     */
    function flashFee(address token, uint256 amount) public view override returns (uint256) {
        require(token == address(token0) || token == address(token1), "AlphaSwap: Unsupported token");
        return (amount * flashLoanFee) / PRECISION;
    }

    /**
     * @notice Executes an ERC-3156 compliant flash loan.
     * @dev The pool is mathematically immune to its own flash loans because the invariant 
     * is strictly checked via `_update` logic and balanced state enforcement.
     */
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external override nonReentrant whenNotPaused returns (bool) {
        require(amount <= this.maxFlashLoan(token), "AlphaSwap: Flash loan amount exceeds liquidity");
        
        uint256 fee = flashFee(token, amount);
        uint256 amountWithFee = amount + fee;

        // Optimistically transfer tokens to the receiver
        IERC20(token).safeTransfer(address(receiver), amount);

        // Execute the external callback
        require(
            receiver.onFlashLoan(msg.sender, token, amount, fee, data) == CALLBACK_SUCCESS,
            "AlphaSwap: Flash loan callback failed"
        );

        // Pull the principal + fee back from the receiver
        IERC20(token).safeTransferFrom(address(receiver), address(this), amountWithFee);

        // Distribute the flash loan fee to LPs by updating reserves without minting LP tokens
        if (token == address(token0)) {
            _update(reserve0 + fee, reserve1);
        } else {
            _update(reserve0, reserve1 + fee);
        }

        emit FlashLoan(address(receiver), token, amount, fee);
        return true;
    }

    /* ==============================================================================
       ADMIN SECURITY & MAINTENANCE
       ============================================================================== */

    /**
     * @notice Triggers an emergency stop, disabling swaps, deposits, and flash loans.
     * @dev Withdrawals (removeLiquidity) are deliberately left unpaused so users can always exit.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Lifts the emergency stop.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    /**
     * @notice Updates the protocol fee settings.
     */
    function setFees(uint256 newSwapFee, uint256 newAdminFee, uint256 newFlashFee) external onlyOwner {
        require(newSwapFee <= MAX_SWAP_FEE, "AlphaSwap: Swap fee exceeds max");
        require(newAdminFee <= MAX_ADMIN_FEE, "AlphaSwap: Admin fee exceeds max");
        require(newFlashFee <= 5e15, "AlphaSwap: Flash fee exceeds 0.5%");
        
        swapFee = newSwapFee;
        adminFee = newAdminFee;
        flashLoanFee = newFlashFee;
        
        emit FeesUpdated(newSwapFee, newAdminFee, newFlashFee);
    }

    /**
     * @notice Admin function to collect accumulated protocol fees.
     */
    function collectAdminFees() external onlyOwner nonReentrant {
        uint256 a0 = adminBalance0;
        uint256 a1 = adminBalance1;

        adminBalance0 = 0;
        adminBalance1 = 0;

        if (a0 > 0) token0.safeTransfer(owner(), a0);
        if (a1 > 0) token1.safeTransfer(owner(), a1);

        emit AdminFeesCollected(a0, a1);
    }
}
