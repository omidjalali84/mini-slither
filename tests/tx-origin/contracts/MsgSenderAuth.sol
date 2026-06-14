// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: uses msg.sender for all authentication.
// tx.origin may still be read (e.g. to block contracts from calling),
// but it is never used as the sole auth check.
contract MsgSenderAuth {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function transferFunds(address payable dest, uint256 amount) public onlyOwner {
        dest.transfer(amount);
    }

    receive() external payable {}
}
