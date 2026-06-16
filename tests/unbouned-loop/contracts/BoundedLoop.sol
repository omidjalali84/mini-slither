// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// SAFE: loop is bounded by a constant MAX_BATCH — gas usage is capped.
contract BoundedLoop {
    uint256 public constant MAX_BATCH = 100;
    mapping(uint256 => uint256) public values;

    function processBatch(uint256 start) public {
        for (uint256 i = start; i < start + MAX_BATCH; i++) {
            values[i] = i * 2;
        }
    }
}
