// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VaultWithOnlyOwner {
    address public owner;

    mapping(address => uint256) public balance;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balance[msg.sender] += msg.value;
    }

    function drain() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
