// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BaselineToken} from "./BaselineToken.sol";

/// @title NaiveHoldsToken
/// @notice Straightforward layout: separate status mapping plus a per-account array
///         of hold amounts that is summed on every transfer. Cost grows with the
///         number of active holds. Used only as a comparison point.
contract NaiveHoldsToken is BaselineToken {
    uint8 internal constant ACTIVE = 0;
    uint8 internal constant BLOCKED = 2;

    mapping(address => uint8) public status;
    mapping(address => uint256[]) internal _holds;
    address public immutable authority;

    error Restricted(address account);
    error InsufficientSpendable();

    constructor(address authority_) {
        authority = authority_;
    }

    function placeHold(address a, uint256 amt) external {
        require(msg.sender == authority, "authority");
        _holds[a].push(amt);
    }

    function setStatus(address a, uint8 s) external {
        require(msg.sender == authority, "authority");
        status[a] = s;
    }

    function _transfer(address from, address to, uint256 amt) internal override {
        if (status[from] != ACTIVE) revert Restricted(from);
        if (status[to] == BLOCKED) revert Restricted(to);
        uint256[] storage h = _holds[from];
        uint256 held;
        uint256 n = h.length;
        for (uint256 i; i < n; ++i) {
            held += h[i];
        }
        if (balanceOf[from] < held + amt) revert InsufficientSpendable();
        super._transfer(from, to, amt);
    }
}
