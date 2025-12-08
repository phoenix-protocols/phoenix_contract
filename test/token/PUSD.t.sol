// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {PUSD} from "src/token/PUSD/PUSD.sol";
import {PUSDStorage} from "src/token/PUSD/PUSDStorage.sol";
import {PUSD_Deployer_Base, PUSDV2} from "script/token/base/PUSD_Deployer_Base.sol";

contract PUSDTest is Test, PUSD_Deployer_Base {
    bytes32 salt;

    PUSD token;
    PUSDV2 tokenV2;

    address admin = address(0xA11CE);
    address user   = address(0xCAFE);

    uint256 constant CAP = 1_000_000_000 * 1e6;

    bytes32 MINTER_ROLE;

    function setUp() public {
        salt = vm.envBytes32("SALT");
        token = _deploy(CAP, admin, salt);

        MINTER_ROLE = token.MINTER_ROLE();
        vm.prank(admin);
        token.grantRole(MINTER_ROLE, admin);
    }

    // ---------- Initialization related ----------

    function test_InitializeState() public {
        assertEq(token.name(), "Phoenix USD Token");
        assertEq(token.symbol(), "PUSD");
        assertEq(token.decimals(), 6);
        assertEq(token.cap(), CAP);
        
        assertTrue(token.hasRole(token.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(token.hasRole(token.MINTER_ROLE(), admin));
    }

    function test_InitializeOnlyOnce() public {
        vm.expectRevert();
        token.initialize(CAP,admin);
    }

    // ---------- Permission & Business Logic ----------

    function test_MinterCanMint() public {
        vm.startPrank(admin);
        token.mint(user, 100 * 1e6);
        assertEq(token.balanceOf(user), 100 * 1e6);
        vm.stopPrank();
    }

    function test_NonMinterCannotMint() public {
        vm.prank(user);
        vm.expectRevert();
        token.mint(user, 100 * 1e6);
    }

    function test_MintRespectsCap() public {
        // First mint to close to cap
        vm.startPrank(admin);
        token.mint(user, CAP - 1);
        assertEq(token.totalSupply(), CAP - 1);

        // Then mint 2 should cap exceeded
        vm.expectRevert(bytes("PUSD: cap exceeded"));
        token.mint(user, 2);

        vm.stopPrank();
    }

    function test_MinterCanBurn() public {
        vm.startPrank(admin);
        token.mint(user, 100 * 1e6);
        token.burn(user, 40 * 1e6);
        vm.stopPrank();

        assertEq(token.balanceOf(user), 60 * 1e6);
    }

    // ---------- MINTER_ROLE Locking Logic ----------

    function test_GrantMinterRoleOnceAndLock() public {
        PUSD grantRoleToken = _deploy(CAP, admin, salt);
        address newMinter = address(0xBEEF);

        assertFalse(grantRoleToken.hasRole(MINTER_ROLE, admin));

        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit PUSDStorage.MinterRoleLocked(admin, admin);
        grantRoleToken.grantRole(MINTER_ROLE, admin);

        assertTrue(grantRoleToken.hasRole(MINTER_ROLE, admin));

        vm.prank(admin);
        vm.expectRevert(bytes("PUSD: MINTER_ROLE permanently locked"));
        grantRoleToken.grantRole(MINTER_ROLE, newMinter);
    }

    function test_CannotRevokeLockedMinterRole() public {
        address newMinter = address(0xBEEF);

        vm.prank(admin);
        vm.expectRevert(bytes("PUSD: Cannot revoke locked MINTER_ROLE"));
        token.revokeRole(MINTER_ROLE, newMinter);
    }

    function test_CannotRenounceLockedMinterRole() public {
        vm.prank(admin);
        vm.expectRevert(bytes("PUSD: Cannot renounce locked MINTER_ROLE"));
        token.renounceRole(MINTER_ROLE, admin);
    }

    function test_GrantAndRevokeOtherRoleStillWorks() public {
        bytes32 OTHER_ROLE = keccak256("OTHER_ROLE");
        address other = address(0xBEEF);

        // grant OTHER_ROLE
        vm.prank(admin);
        token.grantRole(OTHER_ROLE, other);
        assertTrue(token.hasRole(OTHER_ROLE, other));

        // revoke OTHER_ROLE
        vm.prank(admin);
        token.revokeRole(OTHER_ROLE, other);
        assertFalse(token.hasRole(OTHER_ROLE, other));
    }

    function test_RenounceOtherRoleStillWorks() public {
        bytes32 OTHER_ROLE = keccak256("OTHER_ROLE");

        // First grant, lock it
        vm.prank(admin);
        token.grantRole(OTHER_ROLE, admin);
        assertTrue(token.hasRole(OTHER_ROLE, admin));

        // Then renounce
        vm.prank(admin);
        token.renounceRole(OTHER_ROLE, admin);
        assertFalse(token.hasRole(OTHER_ROLE, admin));
    }

    // ---------- Pause Logic ----------

    function test_AdminCanPauseAndUnpause() public {
        vm.prank(admin);
        token.pause();
        assertTrue(token.paused());

        vm.prank(admin);
        token.unpause();
        assertFalse(token.paused());
    }

    function test_MintWhenPausedReverts() public {
        vm.prank(admin);
        token.pause();

        vm.prank(admin);
        vm.expectRevert();
        token.mint(user, 1);
    }

    // ---------- View Functions ----------

    function test_DecimalsReturnsFixedSix() public {
        uint8 d = token.decimals();
        assertEq(d, 6, "decimals() should always return 6");

        vm.prank(admin);
        token.mint(user, 1000);

        assertEq(token.decimals(), 6);
    }


    // ---------- Events ----------

    function test_MintEmitsMintedEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, false, true, true);
        emit PUSDStorage.Minted(user, 100 * 1e6, admin);
        token.mint(user, 100 * 1e6);
    }

    function test_BurnEmitsBurnedEvent() public {
        vm.startPrank(admin);
        token.mint(user, 100 * 1e6);

        vm.expectEmit(true, false, true, true);
        emit PUSDStorage.Burned(user, 40 * 1e6, admin);
        token.burn(user, 40 * 1e6);
        vm.stopPrank();
    }

    function test_NonMinterCannotBurn() public {
        // First mint some state
        vm.prank(admin);
        token.mint(user, 100 * 1e6);

        // user has no MINTER_ROLE, directly calling burn should revert
        vm.prank(user);
        vm.expectRevert();
        token.burn(user, 10 * 1e6);
    }

    // ---------- Upgrade ----------

    function test_UpgradeKeepsStateAndRoles() public {
        // 1. First mint some state on V1
        vm.prank(admin);
        token.mint(user, 123 * 1e6);
        assertEq(token.balanceOf(user), 123 * 1e6);
        assertEq(token.totalSupply(), 123 * 1e6);

        // 2. Upgrade to V2 by admin
        vm.startPrank(admin);
        tokenV2 = _upgrade(address(token), '');
        vm.stopPrank();

        // 3. Previous state is preserved
        assertEq(tokenV2.balanceOf(user), 123 * 1e6);
        assertEq(tokenV2.totalSupply(), 123 * 1e6);
        assertEq(tokenV2.cap(), CAP);
        assertTrue(tokenV2.hasRole(tokenV2.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(tokenV2.hasRole(tokenV2.MINTER_ROLE(), admin));

        // 4. New logic works
        vm.prank(admin);
        tokenV2.setVersion(2);
        assertEq(tokenV2.version(), 2);
    }

    function test_UpgradeOnlyAdmin() public {
        PUSDV2 implV2 = new PUSDV2();

        vm.prank(user);
        vm.expectRevert();
        token.upgradeToAndCall(address(implV2), "");
    }

    // ---------- Additional Tests ----------

    function test_BurnWhenPausedReverts() public {
        vm.prank(admin);
        token.mint(user, 100 * 1e6);

        vm.prank(admin);
        token.pause();

        vm.prank(admin);
        vm.expectRevert();
        token.burn(user, 50 * 1e6);
    }

    function test_PauseOnlyAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        token.pause();
    }

    function test_UnpauseOnlyAdmin() public {
        vm.prank(admin);
        token.pause();

        vm.prank(user);
        vm.expectRevert();
        token.unpause();
    }

    // ---------- ERC20 Transfer Tests ----------

    function test_Transfer() public {
        vm.prank(admin);
        token.mint(user, 100 * 1e6);

        vm.prank(user);
        token.transfer(admin, 30 * 1e6);

        assertEq(token.balanceOf(user), 70 * 1e6);
        assertEq(token.balanceOf(admin), 30 * 1e6);
    }

    function test_TransferInsufficientBalance() public {
        vm.prank(admin);
        token.mint(user, 100 * 1e6);

        vm.prank(user);
        vm.expectRevert();
        token.transfer(admin, 200 * 1e6);
    }

    function test_Approve_And_TransferFrom() public {
        vm.prank(admin);
        token.mint(user, 100 * 1e6);

        vm.prank(user);
        token.approve(admin, 50 * 1e6);

        assertEq(token.allowance(user, admin), 50 * 1e6);

        vm.prank(admin);
        token.transferFrom(user, admin, 50 * 1e6);

        assertEq(token.balanceOf(user), 50 * 1e6);
        assertEq(token.balanceOf(admin), 50 * 1e6);
    }

    function test_TransferFrom_InsufficientAllowance() public {
        vm.prank(admin);
        token.mint(user, 100 * 1e6);

        vm.prank(user);
        token.approve(admin, 30 * 1e6);

        vm.prank(admin);
        vm.expectRevert();
        token.transferFrom(user, admin, 50 * 1e6);
    }

    function test_TotalSupply() public {
        assertEq(token.totalSupply(), 0);

        vm.prank(admin);
        token.mint(user, 100 * 1e6);
        assertEq(token.totalSupply(), 100 * 1e6);

        vm.prank(admin);
        token.burn(user, 30 * 1e6);
        assertEq(token.totalSupply(), 70 * 1e6);
    }

    function test_NameAndSymbol() public view {
        assertEq(token.name(), "Phoenix USD Token");
        assertEq(token.symbol(), "PUSD");
    }

    function test_Cap() public view {
        assertEq(token.cap(), CAP);
    }
}
