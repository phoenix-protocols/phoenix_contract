// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {yPUSD_Deployer_Base} from "./base/yPUSD_Deployer_Base.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract yPUSD_Deployer is Script, yPUSD_Deployer_Base {
    function run() external {
        address pusd_  = vm.envAddress("PUSD");
        uint256 cap_   = vm.envUint("YPUSD_CAP");
        address admin_ = vm.envAddress("ADMIN");

        bytes32 salt = vm.envBytes32("SALT");

        vm.startBroadcast();
        address tokenAddr = address(_deploy(IERC20(pusd_), cap_, admin_, salt));
        vm.stopBroadcast();

        console.log("yPUSD proxy addr:", tokenAddr);

        // If you want to upgrade, please uncomment the following line
        // upgrade();
    }

    function upgrade() external {
        address proxyAddr = vm.envAddress("YPUSD_PROXY");

        bytes memory initData = ""; // If you have reinitializer, you can encode it here

        vm.startBroadcast();
        address tokenV2Addr = address(_upgrade(proxyAddr, initData));
        vm.stopBroadcast();

        console.log("yPUSD proxy addr:", proxyAddr);
        console.log("yPUSDV2 proxy addr:", tokenV2Addr);
    }
}
