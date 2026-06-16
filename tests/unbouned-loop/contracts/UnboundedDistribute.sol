// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: for-loop iterates over recipients.length which grows
// unboundedly as users call register(). Once the array is large enough,
// distributeAll() will exceed the block gas limit and permanently revert.
contract UnboundedDistribute {
    address[] public recipients;
    mapping(address => uint256) public balances;

    function register() public payable {
        recipients.push(msg.sender);
        balances[msg.sender] += msg.value;
    }

    function distributeAll() public {
        for (uint256 i = 0; i < recipients.length; i++) {
            address r = recipients[i];
            uint256 amt = balances[r];
            balances[r] = 0;
            payable(r).transfer(amt);
        }
    }
}
