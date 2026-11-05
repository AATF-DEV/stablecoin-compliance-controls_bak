// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EnforcedToken} from "./EnforcedToken.sol";

/// @title BridgedEnforcedToken
/// @notice EnforcedToken plus the bridge-facing interface of ERC-7281 (xERC20), for issuer-controlled
///         burn-and-mint bridging (paper, Sections 4.1 and 5.6). The issuer deploys one canonical
///         token per chain; allow-listed bridges burn on the source chain and mint on the destination.
///
///   * `burn(user, amt)` (bridge out) applies the same checks as an outbound transfer: the holder is
///     ACTIVE, `amt` does not exceed the spendable balance (held value cannot leave), and the calling
///     bridge is not BLOCKED. A bridge other than the holder spends the holder's allowance.
///   * `mint(to, amt)` by a bridge (bridge in) applies the same check as an inbound transfer: the
///     recipient is not BLOCKED (FROZEN stays receive-only), and the calling bridge is not BLOCKED, so
///     blocking a bridge shuts it in both directions. The minter's primary issuance is unchanged.
///   * Each bridge has a minting and a burning limit that refills linearly over DURATION, as in
///     ERC-7281. Limits are set only by the authority, and every change is logged in the hash chain.
///     Lowering a limit (e.g. to 0 for a compromised bridge) is restrictive; raising it is not.
/// @dev Deviation from ERC-7281: `setLimits` is called by the compliance authority and takes an evidence
///      hash for the audit log; there is no owner and no lockbox. The bridge-facing `mint`/`burn`
///      signatures and the limit views match the standard.
contract BridgedEnforcedToken is EnforcedToken {
    uint256 public constant DURATION = 1 days;

    /// One storage slot per limit.
    struct Limit {
        uint112 max;
        uint112 current; // value available at `timestamp`
        uint32 timestamp;
    }

    struct BridgeLimits {
        Limit minting;
        Limit burning;
    }

    mapping(address => BridgeLimits) internal _bridges;

    uint8 internal constant A_LIMITS = 7;

    event BridgeLimitsSet(address indexed bridge, uint256 mintingLimit, uint256 burningLimit);

    error NotBridge();
    error LimitExceeded();

    constructor(address authority_, address[] memory custodians) EnforcedToken(authority_, custodians) {}

    // ================================================================ ERC-7281 bridge interface
    /// @notice Primary issuance by the minter (unlimited, as in EnforcedToken), or bridge-in by an
    ///         allow-listed bridge within its minting limit.
    function mint(address to, uint256 amt) external override {
        if (msg.sender != minter) {
            Limit storage l = _bridges[msg.sender].minting;
            if (l.max == 0) revert NotMinter();
            // a BLOCKED bridge is shut in both directions, as for burn
            if (_acct[msg.sender].status == BLOCKED) revert Restricted(msg.sender);
            _use(l, amt);
        }
        Account storage t = _acct[to];
        if (t.status == BLOCKED) revert Restricted(to);
        uint256 nb = uint256(t.balance) + amt;
        if (nb > type(uint128).max) revert Overflow();
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded: nb <= type(uint128).max checked above
        t.balance = uint128(nb);
        totalSupply += amt;
        emit Transfer(address(0), to, amt);
    }

    /// @notice Bridge-out: burn `amt` of `user`'s spendable balance.
    function burn(address user, uint256 amt) external {
        Limit storage l = _bridges[msg.sender].burning;
        if (l.max == 0) revert NotBridge();
        if (_acct[msg.sender].status == BLOCKED) revert Restricted(msg.sender); // a blocked bridge is shut
        if (msg.sender != user) {
            uint256 a = allowance[user][msg.sender];
            if (a != type(uint256).max) allowance[user][msg.sender] = a - amt;
        }
        Account memory u = _acct[user];
        if (u.status != ACTIVE) revert Restricted(user); // FROZEN and BLOCKED cannot send value across
        if (uint256(u.balance) - u.held < amt) revert InsufficientSpendable(); // held value cannot leave
        _use(l, amt);
        unchecked {
            // forge-lint: disable-next-line(unsafe-typecast) -- bounded: amt <= balance - held < 2^128
            _acct[user].balance = u.balance - uint128(amt);
        }
        totalSupply -= amt;
        emit Transfer(user, address(0), amt);
    }

    // ================================================================ limits (authority only)
    function setLimits(address bridge, uint256 mintingLimit, uint256 burningLimit, bytes32 evidenceHash)
        external
        onlyAuthority
    {
        if (mintingLimit > type(uint112).max || burningLimit > type(uint112).max) revert Overflow();
        BridgeLimits storage b = _bridges[bridge];
        _change(b.minting, mintingLimit);
        _change(b.burning, burningLimit);
        emit BridgeLimitsSet(bridge, mintingLimit, burningLimit);
        _log(A_LIMITS, keccak256(abi.encode(bridge, mintingLimit, burningLimit)), evidenceHash);
    }

    function mintingMaxLimitOf(address bridge) external view returns (uint256) {
        return _bridges[bridge].minting.max;
    }

    function burningMaxLimitOf(address bridge) external view returns (uint256) {
        return _bridges[bridge].burning.max;
    }

    function mintingCurrentLimitOf(address bridge) external view returns (uint256) {
        return _current(_bridges[bridge].minting);
    }

    function burningCurrentLimitOf(address bridge) external view returns (uint256) {
        return _current(_bridges[bridge].burning);
    }

    // ================================================================ limit arithmetic (ERC-7281)
    /// Available value now: refills linearly at max / DURATION per second, capped at max.
    function _current(Limit memory l) internal view returns (uint256) {
        if (l.current >= l.max) return l.max;
        uint256 elapsed = block.timestamp - l.timestamp;
        if (elapsed >= DURATION) return l.max;
        uint256 c = uint256(l.current) + elapsed * (uint256(l.max) / DURATION);
        return c > l.max ? l.max : c;
    }

    function _use(Limit storage l, uint256 amt) internal {
        uint256 c = _current(l);
        if (amt > c) revert LimitExceeded();
        // forge-lint: disable-next-line(unsafe-typecast) -- c - amt <= max <= type(uint112).max
        l.current = uint112(c - amt);
        // forge-lint: disable-next-line(unsafe-typecast) -- timestamps fit in 32 bits until 2106
        l.timestamp = uint32(block.timestamp);
    }

    /// Changing max shifts the available value by the same difference, never below zero.
    function _change(Limit storage l, uint256 newMax) internal {
        uint256 oldMax = l.max;
        uint256 c = _current(l);
        uint256 nc;
        if (newMax <= oldMax) {
            uint256 d = oldMax - newMax;
            nc = c > d ? c - d : 0;
        } else {
            nc = c + (newMax - oldMax);
        }
        // forge-lint: disable-next-line(unsafe-typecast) -- newMax <= type(uint112).max checked by caller
        l.max = uint112(newMax);
        // forge-lint: disable-next-line(unsafe-typecast) -- nc <= newMax
        l.current = uint112(nc);
        // forge-lint: disable-next-line(unsafe-typecast) -- timestamps fit in 32 bits until 2106
        l.timestamp = uint32(block.timestamp);
    }
}
