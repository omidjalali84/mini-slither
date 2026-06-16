// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: owner can call selfDestruct() at any time to permanently
// destroy the contract and forward all ETH to themselves. Users must
// trust the owner indefinitely — a compromised key loses everything.
contract KillSwitch {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function destroy() public onlyOwner {
        selfdestruct(payable(owner));
    }

    receive() external payable {}
}
