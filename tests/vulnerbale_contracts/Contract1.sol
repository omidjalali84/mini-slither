//SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Test {
    mapping(address => uint256) public balance;

    function withdraw() public {
        msg.sender.call{value: balance[msg.sender]}("");
        balance[msg.sender] = 0;
    }
}
