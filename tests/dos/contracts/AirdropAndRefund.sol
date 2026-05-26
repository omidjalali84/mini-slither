// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Two independent functions both vulnerable to DOS.
// airdrop() and refund() each loop over an unbounded array
// and make external calls — either can be griefed.
contract AirdropAndRefund {
    address[] public participants;
    mapping(address => uint256) public refunds;

    function airdrop(uint256 amount) public {
        for (uint256 i = 0; i < participants.length; i++) {
            participants[i].call{value: amount}("");
        }
    }

    function refundAll() public {
        for (uint256 i = 0; i < participants.length; i++) {
            address user = participants[i];
            uint256 amount = refunds[user];
            refunds[user] = 0;
            payable(user).transfer(amount);
        }
    }
}
