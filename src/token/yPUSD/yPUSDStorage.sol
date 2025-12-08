// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title yPUSD Storage
 * @notice Storage layout for yPUSD ERC-4626 Vault
 */
contract yPUSDStorage {
    /* ========== Constants ========== */
    
    /// @notice Role for injecting yield into the vault
    bytes32 public constant YIELD_INJECTOR_ROLE = keccak256("YIELD_INJECTOR_ROLE");

    /* ========== Storage Variables ========== */
    
    /// @notice Maximum total supply of yPUSD shares
    uint256 public cap;

    /* ========== Events ========== */
    
    /// @notice Emitted when yield is injected into the vault
    event YieldAccrued(uint256 amount, uint256 totalAssets, uint256 newExchangeRate);

    /* ========== Storage Gap ========== */
    
    /// @dev Reserved storage space for future upgrades
    uint256[49] private __gap;
}
