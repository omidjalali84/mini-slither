// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: .transfer() automatically reverts on failure — no return value
// to check.  The analyzer must NOT flag .transfer() calls.
contract TransferSafe {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount); // ✅ auto-reverts on failure
    }
}
