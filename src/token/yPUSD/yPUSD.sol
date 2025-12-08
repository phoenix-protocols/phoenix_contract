// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {yPUSDStorage} from "./yPUSDStorage.sol";

/**
 * @title yPUSD - Yield-bearing PUSD Vault
 * @notice ERC-4626 tokenized vault for PUSD with yield accrual
 * @dev Users deposit PUSD to receive yPUSD shares. 
 *      Yield is injected via accrueYield(), increasing the exchange rate.
 *      
 * Key features:
 * - ERC-4626 compliant: deposit/withdraw/redeem
 * - Yield injection: authorized roles can inject yield to increase share value
 * - Cap limit: maximum total supply of shares
 * - Pausable: admin can pause deposits/withdrawals
 * - Upgradeable: UUPS pattern
 */
contract yPUSD is 
    Initializable, 
    ERC4626Upgradeable, 
    AccessControlUpgradeable, 
    PausableUpgradeable, 
    UUPSUpgradeable, 
    yPUSDStorage 
{
    using SafeERC20 for IERC20;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initialize the yPUSD vault
     * @param _pusd The underlying PUSD token address
     * @param _cap Maximum total supply of yPUSD shares
     * @param admin Administrator address
     */
    function initialize(IERC20 _pusd, uint256 _cap, address admin) public initializer {
        __ERC4626_init(_pusd);
        __ERC20_init("Yield Phoenix USD Token", "yPUSD");
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        cap = _cap;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /* ========== ERC-4626 Overrides ========== */

    /**
     * @dev Override decimals to return 6 (matching PUSD)
     */
    function decimals() public view virtual override(ERC4626Upgradeable) returns (uint8) {
        return 6;
    }

    /**
     * @dev Override maxDeposit to enforce cap
     */
    function maxDeposit(address) public view virtual override returns (uint256) {
        if (paused()) return 0;
        uint256 currentSupply = totalSupply();
        if (currentSupply >= cap) return 0;
        // Convert remaining share capacity to assets
        return _convertToAssets(cap - currentSupply, Math.Rounding.Floor);
    }

    /**
     * @dev Override maxMint to enforce cap
     */
    function maxMint(address) public view virtual override returns (uint256) {
        if (paused()) return 0;
        uint256 currentSupply = totalSupply();
        if (currentSupply >= cap) return 0;
        return cap - currentSupply;
    }

    /**
     * @dev Override maxWithdraw to respect pause
     */
    function maxWithdraw(address owner) public view virtual override returns (uint256) {
        if (paused()) return 0;
        return super.maxWithdraw(owner);
    }

    /**
     * @dev Override maxRedeem to respect pause
     */
    function maxRedeem(address owner) public view virtual override returns (uint256) {
        if (paused()) return 0;
        return super.maxRedeem(owner);
    }

    /**
     * @dev Override _deposit to add pause check and cap enforcement
     */
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal virtual override whenNotPaused {
        require(totalSupply() + shares <= cap, "yPUSD: cap exceeded");
        super._deposit(caller, receiver, assets, shares);
    }

    /**
     * @dev Override _withdraw to add pause check
     */
    function _withdraw(
        address caller,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares
    ) internal virtual override whenNotPaused {
        super._withdraw(caller, receiver, owner, assets, shares);
    }

    /* ========== Yield Injection ========== */

    /**
     * @notice Inject yield into the vault, increasing the exchange rate
     * @dev Only callable by YIELD_INJECTOR_ROLE
     * @param amount Amount of PUSD to inject as yield
     */
    function accrueYield(uint256 amount) external onlyRole(YIELD_INJECTOR_ROLE) {
        require(amount > 0, "yPUSD: zero amount");
        
        IERC20 pusd = IERC20(asset());
        pusd.safeTransferFrom(msg.sender, address(this), amount);
        
        // Calculate new exchange rate (for event)
        uint256 newTotalAssets = totalAssets();
        uint256 supply = totalSupply();
        uint256 newRate = supply > 0 ? (newTotalAssets * 1e18) / supply : 1e18;
        
        emit YieldAccrued(amount, newTotalAssets, newRate);
    }

    /* ========== View Functions ========== */

    /**
     * @notice Get the current exchange rate (assets per share)
     * @return Exchange rate scaled by 1e18
     */
    function exchangeRate() external view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) return 1e18;
        return (totalAssets() * 1e18) / supply;
    }

    /**
     * @notice Get the underlying PUSD value of a user's yPUSD holdings
     * @param user The user address
     * @return The PUSD value
     */
    function underlyingBalanceOf(address user) external view returns (uint256) {
        return convertToAssets(balanceOf(user));
    }

    /* ========== Admin Functions ========== */

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /**
     * @notice Update the cap
     * @param newCap New maximum total supply
     */
    function setCap(uint256 newCap) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newCap >= totalSupply(), "yPUSD: cap below current supply");
        cap = newCap;
    }

    /* ========== UUPS Upgrade ========== */

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}
