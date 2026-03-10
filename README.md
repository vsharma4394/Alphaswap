## Impermanent Loss Example

Impermanent loss happens when the price of tokens in a liquidity pool changes compared to when they were deposited.

### Example

Suppose a liquidity pool has ETH and USDC.

Initial price:
1 ETH = $1000

You deposit:
- 1 ETH
- 1000 USDC

Total value = $2000

The AMM follows the constant product rule:

k = x * y

k = 1 * 1000 = 1000

### Price Change

Now the market price becomes:

1 ETH = $2000

Arbitrage traders rebalance the pool.

New balances become approximately:
- 0.707 ETH
- 1414 USDC

### Liquidity Provider Value

Value after withdrawal:

0.707 × 2000 = 1414  
1414 + 1414 = $2828

### If You Just Held

1 ETH = $2000  
1000 USDC

Total = $3000

### Impermanent Loss

Loss compared to holding:

3000 − 2828 = $172  
≈ **5.7% impermanent loss**
