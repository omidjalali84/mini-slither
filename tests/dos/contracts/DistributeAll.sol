// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DOS via external call in loop.
// If any recipient is a contract that reverts on receive(),
// the entire distribution is permanently blocked.
contract DistributeAll {
    address[] public recipients;
    mapping(address => uint256) public balances;

    function deposit(address recipient) public payable {
        recipients.push(recipient);
        balances[recipient] += msg.value;
    }

    function distributeAll() public {
        for (uint256 i = 0; i < recipients.length; i++) {
            address recipient = recipients[i];
            uint256 amount = balances[recipient];
            balances[recipient] = 0;
            payable(recipient).transfer(amount);
        }
    }
}
