// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

/**
 * @title IyPUSD Interface
 * @notice ERC-4626 tokenized vault interface for yPUSD
 */
interface IyPUSD is IERC4626 {
    /// @notice Get the current exchange rate (assets per share, scaled by 1e18)
    function exchangeRate() external view returns (uint256);
    
    /// @notice Get the underlying PUSD value of a user's yPUSD holdings
    function underlyingBalanceOf(address user) external view returns (uint256);
    
    /// @notice Inject yield into the vault (only YIELD_INJECTOR_ROLE)
    function accrueYield(uint256 amount) external;
    
    /// @notice Maximum total supply of yPUSD shares
    function cap() external view returns (uint256);
    
    /// @notice Update the cap (only admin)
    function setCap(uint256 newCap) external;
}
