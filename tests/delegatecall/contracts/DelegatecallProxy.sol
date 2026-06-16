// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: the delegatecall target is a function parameter — an attacker
// can pass a malicious contract address and overwrite arbitrary storage slots
// in this contract (including the owner variable).
contract DelegatecallProxy {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    // ❌ target is caller-supplied — classic delegatecall injection
    function execute(address target, bytes calldata data) public {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "Delegatecall failed");
    }

    receive() external payable {}
}
