// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {NFTManager} from "src/token/NFTManager/NFTManager.sol";
import {NFTManagerStorage} from "src/token/NFTManager/NFTManagerStorage.sol";
import {NFTManager_Deployer_Base,NFTManagerV2} from "script/token/base/NFTManager_Deployer_Base.sol";
import {IFarm} from "src/interfaces/IFarm.sol";

contract NFTManagerTest is Test, NFTManager_Deployer_Base {
    NFTManager nft;
    NFTManagerV2 nftV2;

    address admin = address(0xA11CE);
    address farm  = address(0xBEEF);
    address user  = address(0xCAFE);

    function setUp() public {
        bytes32 salt = vm.envBytes32("SALT");
        nft = _deploy("Stake NFT", "sNFT", admin, farm, salt);
    }

    // ---------- Initialize & Roles ----------

    function test_InitializeAndRoles() public {
        // name / symbol
        assertEq(nft.name(), "Stake NFT");
        assertEq(nft.symbol(), "sNFT");

        // farm address
        assertEq(nft.farm(), farm);

        // roles
        bytes32 DEFAULT_ADMIN_ROLE = nft.DEFAULT_ADMIN_ROLE();
        bytes32 MINTER_ROLE = nft.MINTER_ROLE();
        bytes32 METADATA_EDITOR_ROLE = nft.METADATA_EDITOR_ROLE();

        assertTrue(nft.hasRole(DEFAULT_ADMIN_ROLE, admin), "admin should have DEFAULT_ADMIN_ROLE");
        assertTrue(nft.hasRole(MINTER_ROLE, farm), "farm should have MINTER_ROLE");
        assertTrue(nft.hasRole(METADATA_EDITOR_ROLE, farm), "farm should have METADATA_EDITOR_ROLE");
    }

    // ---------- Mint & Record ----------

    function test_MintStakeNFT_StoresStakeRecord() public {
        uint256 amount = 100 ether;
        uint64 lockPeriod = 30 days;
        uint16 rewardMultiplier = 1000;
        uint256 pendingReward = 5 ether;

        vm.warp(1_000_000); // Fixed timestamp for easier lastClaimTime assertion

        vm.prank(farm);
        uint256 tokenId = nft.mintStakeNFT(
            user,
            amount,
            lockPeriod,
            rewardMultiplier,
            pendingReward
        );

        assertEq(nft.ownerOf(tokenId), user);
        assertTrue(nft.exists(tokenId));

        IFarm.StakeRecord memory r = nft.getStakeRecord(tokenId);

        assertEq(r.amount, amount);
        assertEq(r.rewardMultiplier, rewardMultiplier);
        assertEq(r.pendingReward, pendingReward);
        assertTrue(r.active);
        assertEq(r.lastClaimTime, uint64(block.timestamp));
    }

    function test_MintStakeNFT_OnlyMinterOrOwner() public {
        uint256 amount = 100 ether;
        uint64 lockPeriod = 30 days;
        uint16 rewardMultiplier = 1000;
        uint256 pendingReward = 5 ether;

        // User should not be able to mint
        vm.prank(user); 
        vm.expectRevert("NFTManager: not authorized to mint");
        nft.mintStakeNFT(
            user,
            amount,
            lockPeriod,
            rewardMultiplier,
            pendingReward
        );
    }

    // ---------- Metadata Editor ----------

    function _mintOne() internal returns (uint256 tokenId) {
        uint256 amount = 100 ether;
        uint64 lockPeriod = 30 days;
        uint16 rewardMultiplier = 1000;
        uint256 pendingReward = 5 ether;

        vm.warp(1_000_000);

        vm.prank(farm);
        tokenId = nft.mintStakeNFT(
            user,
            amount,
            lockPeriod,
            rewardMultiplier,
            pendingReward
        );
    }

    function test_UpdateStakeRecord_ByEditor() public {
        uint256 tokenId = _mintOne();

        uint256 newAmount = 200 ether;
        uint64 newLastClaimTime = uint64(block.timestamp + 100);
        uint16 newRewardMultiplier = 2000;
        bool newActive = false;
        uint256 newPendingReward = 10 ether;

        // If farm has METADATA_EDITOR_ROLE, it can edit
        vm.prank(farm);
        nft.updateStakeRecord(
            tokenId,
            newAmount,
            newLastClaimTime,
            newRewardMultiplier,
            newActive,
            newPendingReward
        );

        IFarm.StakeRecord memory r = nft.getStakeRecord(tokenId);

        assertEq(r.amount, newAmount);
        assertEq(r.lastClaimTime, newLastClaimTime);
        assertEq(r.rewardMultiplier, newRewardMultiplier);
        assertEq(r.active, newActive);
        assertEq(r.pendingReward, newPendingReward);
    }

    function test_UpdateStakeRecord_OnlyEditor() public {
        uint256 tokenId = _mintOne();

        uint256 newAmount = 200 ether;
        uint64 newLastClaimTime = uint64(block.timestamp + 100);
        uint16 newRewardMultiplier = 2000;
        bool newActive = false;
        uint256 newPendingReward = 10 ether;

        vm.prank(user);
        vm.expectRevert("NFTManager: not authorized to edit metadata");
        nft.updateStakeRecord(
            tokenId,
            newAmount,
            newLastClaimTime,
            newRewardMultiplier,
            newActive,
            newPendingReward
        );
    }

    function test_UpdateRewardInfo() public {
        uint256 tokenId = _mintOne();

        uint256 newPendingReward = 123 ether;
        uint64 newLastClaimTime = uint64(block.timestamp + 123);

        vm.prank(farm);
        nft.updateRewardInfo(tokenId, newPendingReward, newLastClaimTime);

        IFarm.StakeRecord memory r = nft.getStakeRecord(tokenId);
        assertEq(r.pendingReward, newPendingReward);
        assertEq(r.lastClaimTime, newLastClaimTime);
    }

    // ---------- Farm Only ----------

    function test_UpdateStakeRecordByFarm_OnlyFarm() public {
        uint256 tokenId = _mintOne();

        IFarm.StakeRecord memory dummy; // Specific fields don't matter, default to 0 is fine

        vm.prank(user);
        vm.expectRevert("NFTManager: only farm can call");
        nft.updateStakeRecord(tokenId, dummy);

        // Farm can call successfully
        vm.prank(farm);
        nft.updateStakeRecord(tokenId, dummy);
    }

    // ---------- TokenURI / BaseURI ----------

    function test_BaseURI_And_TokenURIOverride() public {
        uint256 tokenId = _mintOne();

        // Admin sets baseURI
        vm.prank(admin);
        nft.setBaseURI("ipfs://");

        // When tokenURI is not set, it should use baseURI + tokenId
        string memory uri1 = nft.tokenURI(tokenId);
        assertEq(uri1, "ipfs://1");

        // Farm can set its own tokenURI
        vm.prank(farm);
        nft.setTokenURI(tokenId, "token/1");

        string memory uri2 = nft.tokenURI(tokenId);
        assertEq(uri2, "ipfs://token/1");
    }

    // ---------- Burn ----------

    function test_BurnByEditor_CleansRecordAndURI() public {
        uint256 tokenId = _mintOne();

        vm.prank(farm);
        nft.setTokenURI(tokenId, "uri");

        vm.prank(user);
        nft.approve(farm, tokenId);

        vm.prank(farm);
        nft.burn(tokenId);

        assertFalse(nft.exists(tokenId));

        // ownerOf should revert
        vm.expectRevert();
        nft.ownerOf(tokenId);

        // getStakeRecord should revert
        vm.expectRevert();
        nft.getStakeRecord(tokenId);
    }

    function test_BurnOnlyEditor() public {
        uint256 tokenId = _mintOne();

        vm.prank(user);
        vm.expectRevert("NFTManager: not authorized to edit metadata");
        nft.burn(tokenId);
    }

    // ---------- Upgrade ----------

    function test_UUPSUpgradeAndNewLogic() public {
        uint256 tokenId = _mintOne();

        // 1. Only admin can upgradeToAndCall
        vm.startPrank(admin);
        nftV2 = _upgrade(address(nft), "");
        vm.stopPrank();

        // 2. Old data should be preserved
        assertEq(nftV2.ownerOf(tokenId), user);
        IFarm.StakeRecord memory r = nftV2.getStakeRecord(tokenId);
        assertEq(r.amount, 100 ether);

        // 3. New logic (version) is available
        vm.prank(admin);
        nftV2.setVersion(2);
        assertEq(nftV2.version(), 2);
    }

    function test_UpgradeOnlyAdmin() public {
        NFTManagerV2 implV2 = new NFTManagerV2();

        vm.prank(user);
        vm.expectRevert();
        nft.upgradeToAndCall(address(implV2), "");
    }

    // ---------- Additional Tests ----------

    function test_InitializeOnlyOnce() public {
        vm.expectRevert();
        nft.initialize("Test", "TEST", admin, farm);
    }

    function test_MintStakeNFT_OwnerCanMint() public {
        vm.prank(admin); // admin is owner
        uint256 tokenId = nft.mintStakeNFT(user, 100 ether, 30 days, 1000, 5 ether);
        assertEq(nft.ownerOf(tokenId), user);
    }

    function test_UpdateStakeRecord_RevertNonexistentToken() public {
        vm.prank(farm);
        vm.expectRevert();
        nft.updateStakeRecord(999, 100 ether, uint64(block.timestamp), 1000, true, 0);
    }

    function test_UpdateRewardInfo_OnlyEditor() public {
        uint256 tokenId = _mintOne();

        vm.prank(user);
        vm.expectRevert("NFTManager: not authorized to edit metadata");
        nft.updateRewardInfo(tokenId, 100 ether, uint64(block.timestamp));
    }

    function test_UpdateRewardInfo_RevertNonexistentToken() public {
        vm.prank(farm);
        vm.expectRevert();
        nft.updateRewardInfo(999, 100 ether, uint64(block.timestamp));
    }

    function test_UpdateStakeRecordByFarm_RevertNonexistentToken() public {
        IFarm.StakeRecord memory dummy;
        
        vm.prank(farm);
        vm.expectRevert();
        nft.updateStakeRecord(999, dummy);
    }

    function test_GetStakeRecord_RevertNonexistentToken() public {
        vm.expectRevert();
        nft.getStakeRecord(999);
    }

    function test_SetBaseURI_OnlyAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        nft.setBaseURI("ipfs://");
    }

    function test_SetTokenURI_OnlyEditor() public {
        uint256 tokenId = _mintOne();

        vm.prank(user);
        vm.expectRevert("NFTManager: not authorized to edit metadata");
        nft.setTokenURI(tokenId, "uri");
    }

    function test_SetTokenURI_RevertNonexistentToken() public {
        vm.prank(farm);
        vm.expectRevert();
        nft.setTokenURI(999, "uri");
    }

    function test_TokenURI_WithoutBaseURI() public {
        uint256 tokenId = _mintOne();

        // Set token URI without base URI
        vm.prank(farm);
        nft.setTokenURI(tokenId, "ipfs://QmHash");

        string memory uri = nft.tokenURI(tokenId);
        assertEq(uri, "ipfs://QmHash");
    }

    function test_TokenURI_RevertNonexistentToken() public {
        vm.expectRevert();
        nft.tokenURI(999);
    }

    function test_Burn_RevertNonexistentToken() public {
        vm.prank(farm);
        vm.expectRevert();
        nft.burn(999);
    }

    function test_SupportsInterface() public view {
        // ERC721
        assertTrue(nft.supportsInterface(0x80ac58cd));
        // ERC721Enumerable
        assertTrue(nft.supportsInterface(0x780e9d63));
        // AccessControl
        assertTrue(nft.supportsInterface(0x7965db0b));
        // ERC165
        assertTrue(nft.supportsInterface(0x01ffc9a7));
    }

    // ---------- ERC721Enumerable Tests ----------

    function test_TotalSupply() public {
        assertEq(nft.totalSupply(), 0);

        _mintOne();
        assertEq(nft.totalSupply(), 1);

        vm.prank(farm);
        nft.mintStakeNFT(user, 50 ether, 60 days, 1500, 0);
        assertEq(nft.totalSupply(), 2);
    }

    function test_TokenByIndex() public {
        uint256 tokenId1 = _mintOne();
        
        vm.prank(farm);
        uint256 tokenId2 = nft.mintStakeNFT(admin, 50 ether, 60 days, 1500, 0);

        assertEq(nft.tokenByIndex(0), tokenId1);
        assertEq(nft.tokenByIndex(1), tokenId2);
    }

    function test_TokenByIndex_RevertOutOfBounds() public {
        _mintOne();

        vm.expectRevert();
        nft.tokenByIndex(1);
    }

    function test_TokenOfOwnerByIndex() public {
        uint256 tokenId1 = _mintOne(); // Minted to user
        
        vm.prank(farm);
        uint256 tokenId2 = nft.mintStakeNFT(user, 50 ether, 60 days, 1500, 0);

        assertEq(nft.tokenOfOwnerByIndex(user, 0), tokenId1);
        assertEq(nft.tokenOfOwnerByIndex(user, 1), tokenId2);
        assertEq(nft.balanceOf(user), 2);
    }

    function test_TokenOfOwnerByIndex_RevertOutOfBounds() public {
        _mintOne();

        vm.expectRevert();
        nft.tokenOfOwnerByIndex(user, 1);
    }

    function test_TotalSupply_AfterBurn() public {
        uint256 tokenId = _mintOne();
        assertEq(nft.totalSupply(), 1);

        vm.prank(farm);
        nft.burn(tokenId);
        assertEq(nft.totalSupply(), 0);
    }

    // ---------- Transfer Tests ----------

    function test_TransferFrom() public {
        uint256 tokenId = _mintOne();

        vm.prank(user);
        nft.transferFrom(user, admin, tokenId);

        assertEq(nft.ownerOf(tokenId), admin);
        assertEq(nft.balanceOf(user), 0);
        assertEq(nft.balanceOf(admin), 1);
    }

    function test_SafeTransferFrom() public {
        uint256 tokenId = _mintOne();

        vm.prank(user);
        nft.safeTransferFrom(user, admin, tokenId);

        assertEq(nft.ownerOf(tokenId), admin);
    }

    function test_Approve_And_TransferFrom() public {
        uint256 tokenId = _mintOne();

        vm.prank(user);
        nft.approve(admin, tokenId);

        assertEq(nft.getApproved(tokenId), admin);

        vm.prank(admin);
        nft.transferFrom(user, admin, tokenId);

        assertEq(nft.ownerOf(tokenId), admin);
    }

    function test_SetApprovalForAll() public {
        uint256 tokenId = _mintOne();

        vm.prank(user);
        nft.setApprovalForAll(admin, true);

        assertTrue(nft.isApprovedForAll(user, admin));

        vm.prank(admin);
        nft.transferFrom(user, admin, tokenId);

        assertEq(nft.ownerOf(tokenId), admin);
    }

    // ---------- setFarm Tests ----------

    function test_SetFarm() public {
        address newFarm = address(0x1234);
        
        vm.prank(admin);
        nft.setFarm(newFarm);
        
        assertEq(nft.farm(), newFarm);
        assertTrue(nft.hasRole(nft.MINTER_ROLE(), newFarm));
        assertTrue(nft.hasRole(nft.METADATA_EDITOR_ROLE(), newFarm));
        
        // Old farm should lose roles
        assertFalse(nft.hasRole(nft.MINTER_ROLE(), farm));
        assertFalse(nft.hasRole(nft.METADATA_EDITOR_ROLE(), farm));
    }

    function test_SetFarm_RevertZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert("NFTManager: invalid farm address");
        nft.setFarm(address(0));
    }

    function test_SetFarm_RevertUnauthorized() public {
        vm.prank(user);
        vm.expectRevert("NFTManager: not admin");
        nft.setFarm(address(0x1234));
    }

    function test_Initialize_WithZeroFarm() public {
        // Test that NFTManager can be initialized with zero farm address
        bytes32 salt = keccak256("test_zero_farm");
        NFTManager nft2 = _deploy("Test NFT", "tNFT", admin, address(0), salt);
        
        assertEq(nft2.farm(), address(0));
        assertFalse(nft2.hasRole(nft2.MINTER_ROLE(), address(0)));
        
        // Set farm later
        address newFarm = address(0x5678);
        vm.prank(admin);
        nft2.setFarm(newFarm);
        
        assertEq(nft2.farm(), newFarm);
        assertTrue(nft2.hasRole(nft2.MINTER_ROLE(), newFarm));
    }
}
