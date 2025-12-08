// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {PUSD_Deployer_Base} from "./base/PUSD_Deployer_Base.sol";

contract PUSD_Deployer is Script, PUSD_Deployer_Base {
    function run() external{
        uint256 cap_   = vm.envUint("PUSD_CAP");
        address admin_ = vm.envAddress("ADMIN");

        bytes32 salt = vm.envBytes32("SALT");

        vm.startBroadcast();
        address tokenAddr = address(_deploy(cap_, admin_, salt));
        vm.stopBroadcast();

        console.log("PUSD proxy addr:", tokenAddr);

        // If you want to upgrade, please uncomment the following line
        // upgrade();
    }

    function upgrade() external{
        address proxyAddr = vm.envAddress("PUSD_PROXY");

        bytes memory initData = ""; // If you have reinitializer, you can encode it here

        vm.startBroadcast();
        address tokenV2Addr = address(_upgrade(proxyAddr, initData));
        vm.stopBroadcast();

        console.log("PUSD proxy addr:", proxyAddr);
        console.log("PUSDV2 proxy addr:", tokenV2Addr);
    }
}
