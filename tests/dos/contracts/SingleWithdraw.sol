// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: single external call outside any loop.
// Standard withdraw pattern — no DOS risk.
contract SingleWithdraw {
    mapping(address => uint256) public balance;

    function deposit() public payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balance[msg.sender];
        balance[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
