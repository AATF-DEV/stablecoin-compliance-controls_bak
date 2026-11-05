// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BaselineToken} from "./BaselineToken.sol";

/// @title BlacklistToken
/// @notice Single-flag blacklist kept in a separate mapping, as in the classic
///         Blacklistable pattern (pre-v2.2 USDC style). Checks spender, sender and recipient.
///         The list is modified by `authority` (a ComplianceAuthority or a single key).
contract BlacklistToken is BaselineToken {
    mapping(address => bool) public blacklisted;
    address public immutable authority;

    event Blacklisted(address indexed account);

    error Restricted(address account);

    constructor(address authority_) {
        authority = authority_;
    }

    function blacklistBatch(address[] calldata accounts) external {
        require(msg.sender == authority, "authority");
        for (uint256 i; i < accounts.length; ++i) {
            blacklisted[accounts[i]] = true;
            emit Blacklisted(accounts[i]);
        }
    }

    function _transfer(address from, address to, uint256 amt) internal override {
        if (blacklisted[msg.sender]) revert Restricted(msg.sender);
        if (from != msg.sender && blacklisted[from]) revert Restricted(from);
        if (blacklisted[to]) revert Restricted(to);
        super._transfer(from, to, amt);
    }
}
