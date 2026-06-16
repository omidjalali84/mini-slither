// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: uses a regular call (not delegatecall). The called code runs in
// the target's own storage context — this contract's storage is unaffected.
contract RegularCall {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function callExternal(address target, bytes calldata data) public {
        (bool ok, ) = target.call(data);
        require(ok, "Call failed");
    }
}
