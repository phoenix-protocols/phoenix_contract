// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PUSDStorage {
    uint256 public cap;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // Lock status for MINTER_ROLE: once set to true, can never be modified
    bool public minterRoleLocked;

    // Core business events
    event Minted(address indexed to, uint256 amount, address indexed minter);
    event Burned(address indexed from, uint256 amount, address indexed burner);
    event MinterRoleLocked(address indexed minter, address indexed admin);

    // Placeholder
    uint256[50] private __gap;
}
