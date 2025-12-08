// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFarm {
    /* ========== Structs ========== */

    /* ========== User Asset Information ========== */
    struct UserAssetInfo {
        uint256 totalDeposited;
        uint256 lastActionTime;
        uint256[] tokenIds;
    }

    /* ========== DAO Staking Pool - Each stake recorded independently ========== */
    struct StakeRecord {
        uint256 amount;
        uint256 startTime;
        uint256 lockPeriod;
        uint256 lastClaimTime;
        uint16 rewardMultiplier;
        bool active;
        uint256 pendingReward;
    }

    // Stake detail structure for paginated queries
    struct StakeDetail {
        uint256 tokenId;
        uint256 amount;
        uint256 startTime;
        uint256 lockPeriod;
        uint256 lastClaimTime;
        uint16 rewardMultiplier;
        bool active;
        uint256 currentReward;
        uint256 unlockTime;
        bool isUnlocked;
        uint256 effectiveAPY;
    }

    struct APYRecord {
        uint16 apy;
        uint256 timestamp;
    }
    /* ========== Event Definitions ========== */

    // General asset operation events (deposit/withdraw)
    // true=deposit, false=withdraw
    event AssetOperation(address indexed user, address indexed asset, uint256 amount, uint256 netAmount, bool isDeposit);

    // Fee rate update events
    event FeeRatesUpdated(uint256 depositFee, uint256 withdrawFee, uint256 _bridgeFeeRate);
    // Staking operation events (stake/unstake)
    // true=stake, false=unstake
    event StakeOperation(address indexed user, uint256 tokenId, uint256 amount, uint256 lockPeriod, bool isStake);
    // Staking reward claim events
    event StakeRewardsClaimed(address indexed user, uint256 tokenId, uint256 amount);
    // Base APY update events
    event APYUpdated(uint256 oldAPY, uint256 newAPY, uint256 timestamp);
    // Staking renewal events (renewal/reinvestment)
    // true=compound rewards, false=claim rewards
    event StakeRenewal(address indexed user, uint256 tokenId, uint256 newLockPeriod, uint256 rewardAmount, uint256 newTotalAmount, bool isCompounded);

    // System configuration update events
    event SystemConfigUpdated(uint256 oldMinDeposit, uint256 newMinDeposit, uint256 oldMinLock, uint256 newMinLock, uint256 oldMaxStakes, uint256 newMaxStakes, uint256 oldMaxHistory, uint256 newMaxHistory);

    // Multiplier configuration events
    event MultiplierUpdated(uint256 indexed lockPeriod, uint16 oldMultiplier, uint16 newMultiplier);
    event LockPeriodAdded(uint256 indexed lockPeriod, uint16 multiplier);
    event LockPeriodRemoved(uint256 indexed lockPeriod);
    event NFTManagerUpdated(address indexed nftManager);
    event FarmLendUpdated(address indexed farmLend);

    // Bridge events
    event BridgePUSDInitiated(uint256 indexed sourceChainId, uint256 indexed destChainId, address indexed from, address to, uint256 totalAmount, uint256 netAmount, uint256 fee);
    event BridgePUSDFinalized(uint256 indexed sourceChainId, uint256 indexed destChainId, address indexed from, address to, uint256 amount, uint256 fee, uint256 nonce);
    event BridgeMessengerUpdated(address indexed oldMessenger, address indexed newMessenger);
    event BridgeFeeRateUpdated(uint256 newFeeRate);
    event BridgeChainSupportUpdated(uint256[] chainIds, bool[] isSupported);

    /* ========== Core External Functions ========== */

    function depositAsset(address asset, uint256 amount) external;

    function withdrawAsset(address asset, uint256 pusdAmount) external;

    function stakePUSD(uint256 amount, uint256 lockPeriod) external returns (uint256 tokenId);

    function renewStake(uint256 tokenId, bool compoundRewards, uint256 newLockPeriod) external;

    function unstakePUSD(uint256 tokenId) external;

    function claimStakeRewards(uint256 tokenId) external;

    function claimAllStakeRewards() external returns (uint256 totalReward);

    function getStakeInfo(address account, uint256 queryType, uint256 tokenId, uint256 amount) external view returns (uint256 result, string memory reason);

    function setAPY(uint256 newAPY) external;

    function getSupportedLockPeriodsWithMultipliers() external view returns (uint256[] memory lockPeriods, uint16[] memory multipliers);

    function getUserInfo(address user) external view returns (uint256 pusdBalance, uint256 ypusdBalance, uint256 totalDeposited, uint256 totalStakedAmount, uint256 totalStakeRewards, uint256 activeStakeCount);

    function getStakeDetails(address user, uint256 tokenId) external view returns (StakeRecord memory stakeRecord, uint256 pendingReward, uint256 unlockTime, bool isUnlocked, uint256 remainingTime);

    function getUserStakeDetails(address user, uint256 offset, uint256 limit, bool activeOnly, uint256 lockPeriod) external view returns (StakeDetail[] memory stakeDetails, uint256 totalCount, bool hasMore);

    function getSystemHealth() external view returns (uint256 totalTVL, uint256 totalPUSDMarketCap);

    function batchSetLockPeriodMultipliers(uint256[] calldata lockPeriods, uint16[] calldata multipliers) external;

    function removeLockPeriod(uint256 lockPeriod) external;

    function updateSystemConfig(uint256 configType, uint256 newValue) external;

    function setFeeRates(uint256 _depositFeeRate, uint256 _withdrawFeeRate, uint256 _bridgeFeeRate) external;

    function updateByFarmLend(uint256 tokenId, uint256 pusdAmount) external;

    function pause() external;

    function unpause() external;
}
