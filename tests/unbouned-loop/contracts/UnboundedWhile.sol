// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: while-loop condition depends on users.length which is
// unbounded. Gas exhaustion DOS is possible if enough users are added.
contract UnboundedWhile {
    address[] public users;
    mapping(address => bool) public cleared;

    function addUser(address u) public {
        users.push(u);
    }

    function clearAll() public {
        uint256 i = 0;
        while (i < users.length) {
            cleared[users[i]] = true;
            i++;
        }
    }
}
