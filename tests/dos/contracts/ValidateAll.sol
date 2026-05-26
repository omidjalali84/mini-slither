// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: loop contains only internal calls (require).
// No external calls, so no DOS risk.
contract ValidateAll {
    address[] public whitelist;

    function validateAll() public view {
        for (uint256 i = 0; i < whitelist.length; i++) {
            require(whitelist[i] != address(0), "zero address");
        }
    }
}
