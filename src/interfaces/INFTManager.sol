// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IFarm.sol";

interface INFTManager {
    function exists(uint256 tokenId) external view returns (bool);
    function ownerOf(uint256 tokenId) external view returns (address);
    function getStakeRecord(uint256 tokenId) external view returns (IFarm.StakeRecord memory);
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}
