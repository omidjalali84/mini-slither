// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: tx.origin check hidden inside a custom modifier.
// Any function decorated with onlyRealOwner inherits the vulnerability.
contract TxOriginModifier {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyRealOwner() {
        require(tx.origin == owner, "Not real owner");
        _;
    }

    function adminAction() public onlyRealOwner {
        // privileged action
    }

    receive() external payable {}
}
