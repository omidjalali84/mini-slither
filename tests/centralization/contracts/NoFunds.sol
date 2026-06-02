// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NoFunds {
    address public owner;
    uint256 public value;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setValue(uint256 _value) public onlyOwner {
        value = _value;
    }
}
