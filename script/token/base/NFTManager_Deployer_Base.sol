// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {NFTManager} from "src/token/NFTManager/NFTManager.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// import {NFTManagerV2} from "";
// New contract for upgrade or you can import from other file
contract NFTManagerV2 is NFTManager {
    uint256 public version;

    function setVersion(uint256 v) external onlyAdmin {
        version = v;
    }
}

abstract contract NFTManager_Deployer_Base {
    function _deploy(string memory name_, string memory symbol_, address admin_, address farm_, bytes32 salt) internal returns (NFTManager manager) {
        NFTManager impl = new NFTManager();

        bytes memory initData = abi.encodeCall(
            NFTManager.initialize,
            (name_, symbol_, admin_, farm_)
        );

        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(address(impl), initData);

        manager = NFTManager(address(proxy));
    }

    function _upgrade(address proxyAddr, bytes memory initData) internal returns (NFTManagerV2 managerV2) {
        NFTManagerV2 implV2 = new NFTManagerV2();

        NFTManager proxy = NFTManager(proxyAddr);

        proxy.upgradeToAndCall(address(implV2), initData);

        managerV2 = NFTManagerV2(proxyAddr);
    }
}
