// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: uses tx.origin instead of msg.sender for authentication.
// A phishing contract can trick the owner into calling it; the phishing
// contract then calls transferFunds() and tx.origin == owner passes.
contract TxOriginAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferFunds(address payable dest, uint256 amount) public {
        require(tx.origin == owner, "Not owner");
        dest.transfer(amount);
    }

    receive() external payable {}
}
