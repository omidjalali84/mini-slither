// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AdminWithdrawable {
    address public admin;

    constructor(address _admin) {
        admin = _admin;
    }

    function emergencyWithdraw(address to, uint256 amount) public {
        require(msg.sender == admin, "Not admin");
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
