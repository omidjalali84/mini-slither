// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: loop only modifies state, no external calls.
// Users withdraw individually using the pull pattern.
contract PullPayment {
    mapping(address => uint256) public balances;
    address[] public users;

    function resetExpired() public {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = 0;
        }
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
