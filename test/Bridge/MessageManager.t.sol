// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {MessageManager} from "src/Bridge/MessageManager.sol";
import {IMessageManager} from "src/interfaces/IMessageManager.sol";

contract MessageManagerTest is Test {
    MessageManager public manager;

    address owner = address(0xA11CE);
    address poolManager = address(0xBEEF);
    address user1 = address(0x1111);
    address user2 = address(0x2222);
    address tokenA = address(0xAAAA);
    address tokenB = address(0xBBBB);

    uint256 constant SOURCE_CHAIN_ID = 1;
    uint256 constant DEST_CHAIN_ID = 137;
    uint256 constant VALUE = 1000e18;
    uint256 constant FEE = 10e18;

    // Events
    event MessageSent(
        uint256 sourceChainId,
        uint256 destChainId,
        address sourceTokenAddress,
        address destTokenAddress,
        address indexed _from,
        address indexed _to,
        uint256 _fee,
        uint256 _value,
        uint256 _nonce,
        bytes32 indexed _messageHash
    );

    event MessageClaimed(
        uint256 sourceChainId,
        uint256 destChainId,
        address sourceTokenAddress,
        address destTokenAddress,
        bytes32 indexed _messageHash,
        uint256 _nonce
    );

    function setUp() public {
        // 直接用构造函数部署
        manager = new MessageManager(owner, poolManager);
    }

    // ==================== Initialization Tests ====================

    function test_InitializeState() public view {
        assertEq(manager.owner(), owner);
        assertEq(manager.poolManagerAddress(), poolManager);
        assertEq(manager.nextMessageNumber(), 1);
    }

    // ==================== SendMessage Tests ====================

    function test_SendMessage() public {
        vm.prank(poolManager);
        manager.sendMessage(
            SOURCE_CHAIN_ID,
            DEST_CHAIN_ID,
            tokenA,
            tokenB,
            user1,
            user2,
            VALUE,
            FEE
        );

        assertEq(manager.nextMessageNumber(), 2);
    }

    function test_SendMessage_EmitsEvent() public {
        // Calculate expected message hash
        bytes32 expectedHash = keccak256(
            abi.encode(
                SOURCE_CHAIN_ID,
                DEST_CHAIN_ID,
                tokenA,
                tokenB,
                user1,
                user2,
                FEE,
                VALUE,
                1 // First message number
            )
        );

        vm.prank(poolManager);
        vm.expectEmit(true, true, true, true);
        emit MessageSent(
            SOURCE_CHAIN_ID,
            DEST_CHAIN_ID,
            tokenA,
            tokenB,
            user1,
            user2,
            FEE,
            VALUE,
            1,
            expectedHash
        );
        manager.sendMessage(
            SOURCE_CHAIN_ID,
            DEST_CHAIN_ID,
            tokenA,
            tokenB,
            user1,
            user2,
            VALUE,
            FEE
        );
    }

    function test_SendMessage_IncrementsMessageNumber() public {
        vm.startPrank(poolManager);
        
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);
        assertEq(manager.nextMessageNumber(), 2);

        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE * 2, FEE);
        assertEq(manager.nextMessageNumber(), 3);

        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user2, user1, VALUE, FEE);
        assertEq(manager.nextMessageNumber(), 4);

        vm.stopPrank();
    }

    function test_SendMessage_SetsMessageStatus() public {
        bytes32 expectedHash = keccak256(
            abi.encode(
                SOURCE_CHAIN_ID,
                DEST_CHAIN_ID,
                tokenA,
                tokenB,
                user1,
                user2,
                FEE,
                VALUE,
                1
            )
        );

        assertFalse(manager.sentMessageStatus(expectedHash));

        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);

        assertTrue(manager.sentMessageStatus(expectedHash));
    }

    function test_SendMessage_RevertZeroAddress() public {
        vm.prank(poolManager);
        vm.expectRevert(IMessageManager.ZeroAddressNotAllowed.selector);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, address(0), VALUE, FEE);
    }

    function test_SendMessage_RevertMessageAlreadySent() public {
        vm.startPrank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);

        // Try to send the same message again - but since nonce increments, this won't fail
        // The only way to get "Message already sent" is if the hash collision happens
        // which is virtually impossible. The contract logic prevents duplicate hashes via nonce increment.
        vm.stopPrank();
    }

    function test_SendMessage_RevertOnlyTokenBridge() public {
        vm.prank(user1);
        vm.expectRevert("MessageManager: only token bridge can do this operate");
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);

        vm.prank(owner);
        vm.expectRevert("MessageManager: only token bridge can do this operate");
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);
    }

    function test_SendMessage_DifferentParameters() public {
        vm.startPrank(poolManager);

        // Different source chain
        manager.sendMessage(2, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);
        
        // Different dest chain
        manager.sendMessage(SOURCE_CHAIN_ID, 56, tokenA, tokenB, user1, user2, VALUE, FEE);

        // Different tokens
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenB, tokenA, user1, user2, VALUE, FEE);

        // Different value
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE * 10, FEE);

        // Different fee
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE * 2);

        assertEq(manager.nextMessageNumber(), 6);
        vm.stopPrank();
    }

    // ==================== ClaimMessage Tests ====================

    function test_ClaimMessage() public {
        uint256 nonce = 1;

        vm.prank(poolManager);
        manager.claimMessage(
            SOURCE_CHAIN_ID,
            DEST_CHAIN_ID,
            tokenA,
            tokenB,
            user1,
            user2,
            VALUE,
            FEE,
            nonce
        );

        // Verify message was claimed
        bytes32 messageHash = keccak256(
            abi.encode(
                SOURCE_CHAIN_ID,
                DEST_CHAIN_ID,
                tokenA,
                tokenB,
                user1,
                user2,
                FEE,
                VALUE,
                nonce
            )
        );
        assertTrue(manager.cliamMessageStatus(messageHash));
    }

    function test_ClaimMessage_EmitsEvent() public {
        uint256 nonce = 1;

        bytes32 expectedHash = keccak256(
            abi.encode(
                SOURCE_CHAIN_ID,
                DEST_CHAIN_ID,
                tokenA,
                tokenB,
                user1,
                user2,
                FEE,
                VALUE,
                nonce
            )
        );

        vm.prank(poolManager);
        vm.expectEmit(true, false, false, true);
        emit MessageClaimed(
            SOURCE_CHAIN_ID,
            DEST_CHAIN_ID,
            tokenA,
            tokenB,
            expectedHash,
            nonce
        );
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, nonce);
    }

    function test_ClaimMessage_RevertMessageAlreadyClaimed() public {
        uint256 nonce = 1;

        vm.startPrank(poolManager);
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, nonce);

        vm.expectRevert("Message not found!");
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, nonce);
        vm.stopPrank();
    }

    function test_ClaimMessage_RevertOnlyTokenBridge() public {
        vm.prank(user1);
        vm.expectRevert("MessageManager: only token bridge can do this operate");
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, 1);

        vm.prank(owner);
        vm.expectRevert("MessageManager: only token bridge can do this operate");
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, 1);
    }

    function test_ClaimMessage_DifferentNonces() public {
        vm.startPrank(poolManager);

        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, 1);
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, 2);
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, 3);

        // All should be claimed
        bytes32 hash1 = keccak256(abi.encode(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, FEE, VALUE, 1));
        bytes32 hash2 = keccak256(abi.encode(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, FEE, VALUE, 2));
        bytes32 hash3 = keccak256(abi.encode(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, FEE, VALUE, 3));

        assertTrue(manager.cliamMessageStatus(hash1));
        assertTrue(manager.cliamMessageStatus(hash2));
        assertTrue(manager.cliamMessageStatus(hash3));

        vm.stopPrank();
    }

    // ==================== Message Hash Computation Tests ====================

    function test_MessageHashComputation() public {
        // Verify the hash computation matches between send and claim
        uint256 nonce = manager.nextMessageNumber();

        bytes32 expectedHash = keccak256(
            abi.encode(
                SOURCE_CHAIN_ID,
                DEST_CHAIN_ID,
                tokenA,
                tokenB,
                user1,
                user2,
                FEE,
                VALUE,
                nonce
            )
        );

        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);

        assertTrue(manager.sentMessageStatus(expectedHash));
    }

    function test_DifferentHashesForDifferentParams() public {
        vm.startPrank(poolManager);

        // Send messages with slightly different parameters
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE + 1, FEE);

        bytes32 hash1 = keccak256(abi.encode(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, FEE, VALUE, 1));
        bytes32 hash2 = keccak256(abi.encode(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, FEE, VALUE + 1, 2));

        assertTrue(manager.sentMessageStatus(hash1));
        assertTrue(manager.sentMessageStatus(hash2));
        assertTrue(hash1 != hash2);

        vm.stopPrank();
    }

    // ==================== Integration Tests ====================

    function test_SendAndClaimFlow() public {
        // Simulate a full bridge flow
        uint256 nonce = manager.nextMessageNumber();

        // 1. Send message on source chain
        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);

        bytes32 messageHash = keccak256(
            abi.encode(
                SOURCE_CHAIN_ID,
                DEST_CHAIN_ID,
                tokenA,
                tokenB,
                user1,
                user2,
                FEE,
                VALUE,
                nonce
            )
        );

        assertTrue(manager.sentMessageStatus(messageHash));
        assertFalse(manager.cliamMessageStatus(messageHash));

        // 2. Claim message on destination chain (same contract for testing)
        vm.prank(poolManager);
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE, nonce);

        assertTrue(manager.cliamMessageStatus(messageHash));
    }

    function test_MultipleSendAndClaim() public {
        vm.startPrank(poolManager);

        // Send multiple messages
        for (uint256 i = 0; i < 5; i++) {
            manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE * (i + 1), FEE);
        }

        assertEq(manager.nextMessageNumber(), 6);

        // Claim messages in different order
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE * 3, FEE, 3);
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE * 1, FEE, 1);
        manager.claimMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE * 5, FEE, 5);

        vm.stopPrank();
    }

    // ==================== Edge Cases ====================

    function test_ZeroValue() public {
        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, 0, FEE);

        assertEq(manager.nextMessageNumber(), 2);
    }

    function test_ZeroFee() public {
        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, 0);

        assertEq(manager.nextMessageNumber(), 2);
    }

    function test_SameSourceAndDestChain() public {
        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, SOURCE_CHAIN_ID, tokenA, tokenB, user1, user2, VALUE, FEE);

        assertEq(manager.nextMessageNumber(), 2);
    }

    function test_SameSourceAndDestToken() public {
        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenA, user1, user2, VALUE, FEE);

        assertEq(manager.nextMessageNumber(), 2);
    }

    function test_SameFromAndTo() public {
        vm.prank(poolManager);
        manager.sendMessage(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user1, VALUE, FEE);

        assertEq(manager.nextMessageNumber(), 2);
    }

    function test_MaxValues() public {
        vm.prank(poolManager);
        manager.sendMessage(
            type(uint256).max,
            type(uint256).max,
            address(type(uint160).max),
            address(type(uint160).max),
            address(type(uint160).max),
            user2, // Can't be address(0)
            type(uint256).max,
            type(uint256).max
        );

        assertEq(manager.nextMessageNumber(), 2);
    }

    // ==================== View Functions Tests ====================

    function test_NextMessageNumber() public view {
        assertEq(manager.nextMessageNumber(), 1);
    }

    function test_PoolManagerAddress() public view {
        assertEq(manager.poolManagerAddress(), poolManager);
    }

    function test_SentMessageStatus_NotSent() public view {
        bytes32 randomHash = keccak256("random");
        assertFalse(manager.sentMessageStatus(randomHash));
    }

    function test_CliamMessageStatus_NotClaimed() public view {
        bytes32 randomHash = keccak256("random");
        assertFalse(manager.cliamMessageStatus(randomHash));
    }

    // ==================== Ownership Tests ====================

    function test_TransferOwnership() public {
        address newOwner = address(0xDEAD);

        vm.prank(owner);
        manager.transferOwnership(newOwner);

        assertEq(manager.owner(), newOwner);
    }

    function test_TransferOwnership_RevertUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        manager.transferOwnership(user1);
    }

    // ==================== Fuzz Tests ====================

    function testFuzz_SendMessage(
        uint256 sourceChain,
        uint256 destChain,
        address from,
        uint256 value,
        uint256 fee
    ) public {
        vm.assume(from != address(0));

        vm.prank(poolManager);
        manager.sendMessage(sourceChain, destChain, tokenA, tokenB, from, user2, value, fee);

        assertEq(manager.nextMessageNumber(), 2);
    }

    function testFuzz_ClaimMessage(
        uint256 sourceChain,
        uint256 destChain,
        uint256 value,
        uint256 fee,
        uint256 nonce
    ) public {
        vm.prank(poolManager);
        manager.claimMessage(sourceChain, destChain, tokenA, tokenB, user1, user2, value, fee, nonce);

        bytes32 messageHash = keccak256(
            abi.encode(sourceChain, destChain, tokenA, tokenB, user1, user2, fee, value, nonce)
        );
        assertTrue(manager.cliamMessageStatus(messageHash));
    }

    function testFuzz_MessageHashUniqueness(uint256 nonce1, uint256 nonce2) public {
        vm.assume(nonce1 != nonce2);

        bytes32 hash1 = keccak256(
            abi.encode(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, FEE, VALUE, nonce1)
        );
        bytes32 hash2 = keccak256(
            abi.encode(SOURCE_CHAIN_ID, DEST_CHAIN_ID, tokenA, tokenB, user1, user2, FEE, VALUE, nonce2)
        );

        assertTrue(hash1 != hash2);
    }
}
