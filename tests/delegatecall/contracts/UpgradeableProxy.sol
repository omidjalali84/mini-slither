// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// MEDIUM RISK: delegatecall target is a fixed state variable set by the owner,
// not a user parameter. Still dangerous if the implementation contract is
// compromised or has a storage layout mismatch, but the attack surface is
// narrower than a fully user-controlled target.
contract UpgradeableProxy {
    address public owner;
    address public implementation; // set by owner

    constructor(address _impl) {
        owner = msg.sender;
        implementation = _impl;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function upgradeTo(address newImpl) public onlyOwner {
        implementation = newImpl;
    }

    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok, "Delegatecall failed");
    }

    receive() external payable {}
}
