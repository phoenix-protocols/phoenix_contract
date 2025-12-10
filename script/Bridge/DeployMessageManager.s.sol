// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {MessageManager} from "src/Bridge/MessageManager.sol";

/**
 * @title DeployMessageManager
 * @notice Deploys MessageManager for cross-chain bridge functionality
 * @dev Uses CREATE2 for deterministic addresses across all chains
 * 
 * Environment Variables:
 *   - ADMIN: Owner address
 *   - FARM: Farm contract address (poolManager for bridge - calls sendMessage)
 *   - SALT: CREATE2 salt for deterministic deployment
 * 
 * Usage:
 *   forge script script/Bridge/DeployMessageManager.s.sol:DeployMessageManager \
 *     --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
 */
contract DeployMessageManager is Script {
    function run() external {
        // Load config
        address admin = vm.envAddress("ADMIN");
        address farm = vm.envAddress("FARM");
        bytes32 salt = vm.envBytes32("SALT");

        console.log("=== MessageManager Deployment ===");
        console.log("Admin:", admin);
        console.log("Farm (PoolManager):", farm);
        console.log("Salt:", vm.toString(salt));
        console.log("");

        vm.startBroadcast();

        // Deploy with CREATE2 - single transaction, deterministic address
        // Farm is the poolManager because Farm.bridgeInitiatePUSD() calls MessageManager.sendMessage()
        MessageManager messageManager = new MessageManager{salt: salt}(admin, farm);
        console.log("MessageManager:", address(messageManager));

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Complete ===");
        console.log("MESSAGE_MANAGER=", address(messageManager));
        console.log("");
        console.log("Next Steps:");
        console.log("1. Add MESSAGE_MANAGER to .env");
        console.log("2. Run: farm.setBridgeMessenger(MESSAGE_MANAGER)");
    }
}
