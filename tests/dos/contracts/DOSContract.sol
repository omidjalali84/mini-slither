// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DOSVulnerable {
    address[] public recipients;
    mapping(address => uint256) public balances;

    function depositFor(address recipient) public payable {
        recipients.push(recipient);
        balances[recipient] += msg.value;
    }

    // Vulnerable: external call (transfer) inside a for loop.
    // If any recipient is a contract that reverts on receive,
    // the entire payout is permanently blocked.
    function distributeAll() public {
        for (uint256 i = 0; i < recipients.length; i++) {
            address recipient = recipients[i];
            uint256 amount = balances[recipient];
            balances[recipient] = 0;
            payable(recipient).transfer(amount); // <-- DOS risk
        }
    }
}
