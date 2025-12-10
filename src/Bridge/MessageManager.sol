// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./MessageManagerStorage.sol";

/**
 * @title MessageManager
 * @notice Cross-chain message manager for PUSD bridge
 * @dev Uses constructor initialization (not upgradeable) with CREATE2 for deterministic addresses
 */
contract MessageManager is
    ReentrancyGuard,
    Ownable,
    MessageManagerStorage
{
    constructor(address initialOwner, address _poolManagerAddress) Ownable(initialOwner) {
        poolManagerAddress = _poolManagerAddress;
        nextMessageNumber = 1;
    }

    modifier onlyTokenBridge() {
        require(
            msg.sender == poolManagerAddress,
            "MessageManager: only token bridge can do this operate"
        );
        _;
    }

    function sendMessage(
        uint256 sourceChainId,
        uint256 destChainId,
        address sourceTokenAddress,
        address destTokenAddress,
        address _from,
        address _to,
        uint256 _value,
        uint256 _fee
    ) external onlyTokenBridge {
        if (_to == address(0)) {
            revert ZeroAddressNotAllowed();
        }
        // Generate message hash
        uint256 messageNumber = nextMessageNumber;
        bytes32 messageHash = keccak256(
            abi.encode(
                sourceChainId,
                destChainId,
                sourceTokenAddress,
                destTokenAddress,
                _from,
                _to,
                _fee,
                _value,
                messageNumber
            )
        );
        nextMessageNumber++;

        // Ensure the message wont't be sent again
        require(!sentMessageStatus[messageHash], "Message already sent!");
        sentMessageStatus[messageHash] = true;
        emit MessageSent(
            sourceChainId,
            destChainId,
            sourceTokenAddress,
            destTokenAddress,
            _from,
            _to,
            _fee,
            _value,
            messageNumber,
            messageHash
        );
    }

    function claimMessage(
        uint256 sourceChainId,
        uint256 destChainId,
        address sourceTokenAddress,
        address destTokenAddress,
        address _from,
        address _to,
        uint256 _value,
        uint256 _fee,
        uint256 _nonce
    ) external onlyTokenBridge nonReentrant() {
        // Generate message hash
        bytes32 messageHash = keccak256(
            abi.encode(
                sourceChainId,
                destChainId,
                sourceTokenAddress,
                destTokenAddress,
                _from,
                _to,
                _fee,
                _value,
                _nonce
            )
        );

        // Ensure the message wont't be claimed again
        require(!cliamMessageStatus[messageHash], "Message not found!");
        cliamMessageStatus[messageHash] = true;
        emit MessageClaimed(
            sourceChainId,
            destChainId,
            sourceTokenAddress,
            destTokenAddress,
            messageHash,
            _nonce
        );
    }
}