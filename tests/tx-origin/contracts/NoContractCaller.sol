// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: tx.origin is read but only to prevent contracts from calling,
// NOT as the sole authentication mechanism.
// The actual privileged check still uses msg.sender.
contract NoContractCaller {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Rejects calls originating from contract wallets (EOA-only guard).
    // This is debatable design but is NOT a tx.origin auth vulnerability
    // because msg.sender is used for the privileged owner check.
    function sensitiveAction() public {
        require(msg.sender == owner, "Not owner");
        require(tx.origin == msg.sender, "No contract callers");
        // action...
    }
}
