// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// VULNERABLE: return value of .call() is completely ignored.
// If the external call fails (e.g. recipient reverts), execution
// continues as if nothing happened — ETH is NOT actually sent
// but the contract acts as though it was.
contract UncheckedCall {
    function sendEth(address payable dest, uint256 amount) public {
        dest.call{value: amount}(""); // ❌ return value discarded
    }

    receive() external payable {}
}
