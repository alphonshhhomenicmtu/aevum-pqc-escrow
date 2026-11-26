// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PqcInvoiceEscrow} from "../src/PqcInvoiceEscrow.sol";

interface VmDeploy {
    function envUint(string calldata name) external view returns (uint256);
    function envOr(string calldata name, address defaultValue) external view returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DeployPqcInvoiceEscrow {
    VmDeploy private constant vm = VmDeploy(address(uint160(uint256(keccak256("hevm cheat code")))));

    // Official tUSD8 on QDay Aevum Testnet (Chain ID 44005)
    address public constant DEFAULT_TUSD8 = 0x456569838f1d43009A91ebA4263147Afd7233483;

    function run() external returns (PqcInvoiceEscrow deployed) {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address tusd8 = vm.envOr("TUSD8_ADDRESS", DEFAULT_TUSD8);

        vm.startBroadcast(pk);
        deployed = new PqcInvoiceEscrow(tusd8);
        vm.stopBroadcast();
    }
}
