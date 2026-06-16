// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: every internal/private state variable is referenced in at least
// one function or modifier body.
contract AllVarsUsed {
    address internal owner;
    uint256 internal counter;

    constructor() {
        owner = msg.sender;
        counter = 0;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function increment() public onlyOwner {
        counter += 1;
    }

    function getCounter() public view returns (uint256) {
        return counter;
    }
}
