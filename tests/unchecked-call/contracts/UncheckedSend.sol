// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: .send() returns false on failure instead of reverting,
// but the return value is never checked — silent failures possible.
contract UncheckedSend {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).send(amount); // ❌ return value discarded
    }
}
