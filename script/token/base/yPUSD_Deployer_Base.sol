// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {yPUSD} from "src/token/yPUSD/yPUSD.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// import {yPUSDV2} from "";
// New contract for upgrade or you can import from other file
contract yPUSDV2 is yPUSD {
    uint256 public version;

    function setVersion(uint256 v) external onlyRole(DEFAULT_ADMIN_ROLE) {
        version = v;
    }
}

abstract contract yPUSD_Deployer_Base {
    function _deploy(IERC20 pusd_, uint256 cap_, address admin_, bytes32 salt) internal returns (yPUSD token) {
        yPUSD impl = new yPUSD();

        bytes memory initData = abi.encodeCall(
            yPUSD.initialize,
            (
                pusd_,
                cap_, 
                admin_
            )
        );

        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(address(impl), initData);

        token = yPUSD(address(proxy));
    }

    // UUPS upgrade
    function _upgrade(address proxyAddr, bytes memory initData) internal returns (yPUSDV2 tokenV2) {
        yPUSDV2 implV2 = new yPUSDV2();

        yPUSD proxy = yPUSD(proxyAddr); // old version

        proxy.upgradeToAndCall(address(implV2), initData);

        tokenV2 = yPUSDV2(proxyAddr);
    }
}
