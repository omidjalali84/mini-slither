// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: selfdestruct() has no access control — anyone can
// destroy the contract and forward its ETH balance to an arbitrary address.
contract UnprotectedKill {
    constructor() payable {}

    function kill(address payable recipient) public {
        selfdestruct(recipient);
    }

    receive() external payable {}
}
