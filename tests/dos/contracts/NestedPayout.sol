// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// External call buried inside a nested loop.
// Outer loop iterates over groups, inner loop over members.
// One reverting member blocks the entire nested execution.
contract NestedPayout {
    address[][] public groups;

    function payoutAll(uint256 amountPerMember) public payable {
        for (uint256 i = 0; i < groups.length; i++) {
            for (uint256 j = 0; j < groups[i].length; j++) {
                payable(groups[i][j]).transfer(amountPerMember);
            }
        }
    }
}
