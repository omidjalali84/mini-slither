// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: follows the Checks-Effects-Interactions pattern.
// The balance is zeroed out BEFORE the external call, so a re-entrant
// call to withdraw() would find balance[msg.sender] == 0 and send nothing.
contract Safe {
    mapping(address => uint256) public balance;

    function deposit() public payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balance[msg.sender];

        // ✅ Step 1 — state update first (Effects)
        balance[msg.sender] = 0;
        // Step 2 — local changes
        uint256 a;
        uint256 b;
        uint256 c = a + b;
        // ✅ Step 3 — external call last (Interactions)
        msg.sender.call{value: amount}("");
    }
}
