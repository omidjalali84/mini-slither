// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: all state variables are public — their auto-generated getter
// constitutes usage. The analyzer must NOT flag public variables.
contract PublicVarsOnly {
    address public owner;
    uint256 public totalSupply;
    bool public paused;

    constructor() {
        owner = msg.sender;
        totalSupply = 1_000_000;
        paused = false;
    }
}
