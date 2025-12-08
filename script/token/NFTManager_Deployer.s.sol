// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {NFTManager_Deployer_Base} from "./base/NFTManager_Deployer_Base.sol";

contract NFTManager_Deployer is Script, NFTManager_Deployer_Base {
    function run() external{
        string memory name_   = vm.envString("NAME");
        string memory symbol_ = vm.envString("SYMBOL");
        address admin_ = vm.envAddress("ADMIN");
        address farm_ = vm.envAddress("FARM");

        bytes32 salt = vm.envBytes32("SALT");

        vm.startBroadcast();
        address nftManagerAddr = address(_deploy(name_, symbol_, admin_, farm_, salt));
        vm.stopBroadcast();

        console.log("NFTManager proxy addr:", nftManagerAddr);

        // upgrade();
    }

    function upgrade() external{
        address proxyAddr = vm.envAddress("NFTMANAGER_PROXY");

        bytes memory initData = ""; // If you have reinitializer, you can encode it here

        vm.startBroadcast();
        address nftManagerV2Addr = address(_upgrade(proxyAddr, initData));
        vm.stopBroadcast();

        console.log("NFTManager proxy addr:", proxyAddr);
        console.log("NFTManagerV2 proxy addr:", nftManagerV2Addr);
    }
}