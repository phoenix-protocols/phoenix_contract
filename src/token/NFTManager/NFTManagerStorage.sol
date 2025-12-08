// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IFarm.sol";

contract NFTManagerStorage {
    // ---------- Roles ----------
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant METADATA_EDITOR_ROLE = keccak256("METADATA_EDITOR_ROLE");

    address public farm;

    // tokenId => IFarm.StakeRecord
    mapping(uint256 => IFarm.StakeRecord) internal _stakeRecords;

    // Optional: On-chain tokenURI storage
    mapping(uint256 => string) internal _tokenURIs;
    string internal _baseTokenURI;

    uint256 internal _tokenIdTracker;

    // ---------- Events ----------
    event StakeNFTMinted(uint256 indexed tokenId, address indexed owner, uint256 amount, uint256 startTime, uint256 lockPeriod, uint16 rewardMultiplier, uint256 pendingReward);

    event StakeRecordUpdated(uint256 indexed tokenId, uint256 amount, uint256 lastClaimTime, uint16 rewardMultiplier, bool active, uint256 pendingReward);

    event BaseURIUpdated(string newBaseURI);
    event MinterRoleLocked(address indexed account, address indexed admin);
    event FarmUpdated(address indexed newFarm);
}
