// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BaselineToken} from "./BaselineToken.sol";

/// @title AggregateHoldsToken
/// @notice Separate-storage comparison point with a constant-cost transfer path: a status
///         mapping plus one aggregate held amount per account (the bookkeeping ERC-3643 uses
///         for partial freezes). Unlike NaiveHoldsToken, its transfer cost does not depend on
///         the number of holds; unlike EnforcedToken, the compliance state lives outside the
///         balance slot and costs extra cold reads. Used only as a comparison point.
contract AggregateHoldsToken is BaselineToken {
    uint8 internal constant ACTIVE = 0;
    uint8 internal constant BLOCKED = 2;

    mapping(address => uint8) public status;
    mapping(address => uint256) public held;
    address public immutable authority;

    error Restricted(address account);
    error InsufficientSpendable();

    constructor(address authority_) {
        authority = authority_;
    }

    function placeHold(address a, uint256 amt) external {
        require(msg.sender == authority, "authority");
        held[a] += amt;
    }

    function setStatus(address a, uint8 s) external {
        require(msg.sender == authority, "authority");
        status[a] = s;
    }

    function _transfer(address from, address to, uint256 amt) internal override {
        if (status[from] != ACTIVE) revert Restricted(from);
        if (status[to] == BLOCKED) revert Restricted(to);
        if (balanceOf[from] < held[from] + amt) revert InsufficientSpendable();
        super._transfer(from, to, amt);
    }
}
