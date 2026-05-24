// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: external call happens BEFORE the state variable is updated.
// An attacker contract can re-enter withdraw() while balance[msg.sender]
// is still non-zero and drain the contract.
contract Vulnerable {
    mapping(address => uint256) public balance;

    function deposit() public payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw() public {
        // ❌ Step 1 — external call (triggers attacker's receive())
        msg.sender.call{value: balance[msg.sender]}("");
        // ❌ Step 2 — state update comes too late
        balance[msg.sender] = 0;
    }
}
