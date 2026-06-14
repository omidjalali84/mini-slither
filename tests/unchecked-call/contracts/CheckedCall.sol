// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: return value of .call() is captured in a tuple and then
// checked with require().  This is the recommended pattern.
contract CheckedCall {
    function sendEth(address payable dest, uint256 amount) public {
        (bool ok, ) = dest.call{value: amount}(""); // ✅ captured
        require(ok, "Transfer failed");              // ✅ checked
    }

    receive() external payable {}
}
