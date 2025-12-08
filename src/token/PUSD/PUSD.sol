// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./PUSDStorage.sol";

contract PUSD is Initializable, ERC20Upgradeable, AccessControlUpgradeable, PausableUpgradeable, UUPSUpgradeable, PUSDStorage {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // This code will not execute on the implementation contract
    // Can only be called through proxy contract
    // This function can never be called on the implementation contract
    function initialize(uint256 _cap, address admin) public initializer {
        __ERC20_init("Phoenix USD Token", "PUSD");
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        cap = _cap;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // Note: Paused/Unpaused events are already defined in PausableUpgradeable
    // Note: Upgraded event is already defined in UUPSUpgradeable

    /**
     * @dev Override grantRole function to ensure MINTER_ROLE can only be granted once
     * Once MINTER_ROLE is granted, minterRoleLocked will be set to true,
     * after which no one (including DEFAULT_ADMIN_ROLE) can grant or revoke MINTER_ROLE again
     */
    function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (role == MINTER_ROLE) {
            require(!minterRoleLocked, "PUSD: MINTER_ROLE permanently locked");

            // Check if role is already granted (for upgrade compatibility)
            bool alreadyHasRole = hasRole(role, account);

            if (!alreadyHasRole) {
                // Execute normal role granting
                super.grantRole(role, account);
            }

            // Permanently lock MINTER_ROLE, cannot be modified thereafter
            minterRoleLocked = true;
            emit MinterRoleLocked(account, msg.sender);
        } else {
            // Handle other roles normally
            super.grantRole(role, account);
        }
    }

    /**
     * @dev Override revokeRole function to prevent revoking locked MINTER_ROLE
     * Even DEFAULT_ADMIN_ROLE cannot revoke a locked MINTER_ROLE
     */
    function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (role == MINTER_ROLE && minterRoleLocked) {
            revert("PUSD: Cannot revoke locked MINTER_ROLE");
        }

        super.revokeRole(role, account);
    }

    /**
     * @dev Override renounceRole function to prevent holders from renouncing locked MINTER_ROLE
     * Even the MINTER_ROLE holder cannot voluntarily renounce the role
     */
    function renounceRole(bytes32 role, address account) public override {
        if (role == MINTER_ROLE && minterRoleLocked) {
            revert("PUSD: Cannot renounce locked MINTER_ROLE");
        }

        super.renounceRole(role, account);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        require(totalSupply() + amount <= cap, "PUSD: cap exceeded");
        _mint(to, amount);
        emit Minted(to, amount, msg.sender);
    }

    function burn(address from, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        _burn(from, amount);
        emit Burned(from, amount, msg.sender);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
        // PausableUpgradeable will automatically trigger Paused(msg.sender) event
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
        // PausableUpgradeable will automatically trigger Unpaused(msg.sender) event
    }

    /**
     * @dev Override decimals function, set to 6 decimal places
     * @return Token decimal places (6 digits, consistent with USDT/USDC)
     */
    function decimals() public view virtual override returns (uint8) {
        return 6;
    }

    /**
     * @dev Upgrade authorization check - only admin can upgrade
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {
        // Admin permission is sufficient, no additional verification needed
    }
}
