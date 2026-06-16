// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: no selfdestruct() anywhere. The contract cannot be destroyed.
contract NoKillSwitch {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
