// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: declares state variables that are never read or written
// in any function body. Dead variables waste storage and deployment gas.
contract UnusedVars {
    address internal owner;       // ✅ used — set in constructor, read in modifier
    uint256 internal unusedLimit; // ❌ never referenced anywhere
    bool internal deprecated;     // ❌ never referenced anywhere

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function doSomething() public onlyOwner {
        // owner is referenced via the modifier; unusedLimit and deprecated are not
    }
}
