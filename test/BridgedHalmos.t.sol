// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {HalmosProofs} from "./Halmos.t.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";
import {BridgedEnforcedToken} from "../src/BridgedEnforcedToken.sol";

/// Symbolic proofs for BridgedEnforcedToken (run with `halmos --contract BridgedProofs`).
///
/// Inherits every check of HalmosProofs and runs them against the bridged token, so Invariants
/// 1-4 and 6 and the authority gate are re-proved for it. Adds:
///   B1  bridge-out (`burn`) only by an allow-listed, non-blocked bridge within its burning limit;
///       the holder is ACTIVE; at most the spendable balance leaves; held value and every other
///       account and hold are untouched; supply falls by exactly the amount; the log is untouched;
///       a bridge other than the holder spends exactly `amt` of the holder's finite allowance.
///   B2  bridge-in (`mint` by a non-minter) only by an allow-listed, non-blocked bridge within its
///       minting limit and never to a BLOCKED account; supply rises by exactly the amount.
///   B3  limits change only through the authority; each change sets both maxima, keeps the
///       available value within them, and appends exactly the specified log entry.
/// Adds read-only access to the stored limit fields; no behaviour is changed.
contract BridgedHarness is BridgedEnforcedToken {
    constructor(address authority_) BridgedEnforcedToken(authority_, new address[](0)) {}

    function rawMinting(address b) external view returns (uint256 max, uint256 current, uint256 ts) {
        Limit memory l = _bridges[b].minting;
        return (l.max, l.current, l.timestamp);
    }

    function rawBurning(address b) external view returns (uint256 max, uint256 current, uint256 ts) {
        Limit memory l = _bridges[b].burning;
        return (l.max, l.current, l.timestamp);
    }
}

contract BridgedProofs is HalmosProofs {
    uint256 internal lim0;

    function setUp() public override {
        t = new BridgedHarness(AUTH); // minter = this
        svm.enableSymbolicStorage(address(t));
    }

    function _bt() internal view returns (BridgedHarness) {
        return BridgedHarness(address(t));
    }

    /// A non-minter can mint only as an allow-listed bridge within its limit (replaces the base check).
    function check_mintOnlyMinter(address caller, address to, uint256 amt) public override {
        vm.assume(caller != address(this));
        lim0 = _bt().mintingCurrentLimitOf(caller);
        uint256 max0 = _bt().mintingMaxLimitOf(caller);
        bool ok = _call(caller, abi.encodeCall(EnforcedToken.mint, (to, amt)));
        if (!ok) return;
        assert(max0 > 0 && amt <= lim0);
    }

    // ============================================================ B1: bridge-out
    function check_bridgeBurn(address bridge, address user, uint256 amt, address o, bytes32 id2) public {
        vm.assume(_wf(user) && _wf(bridge));
        vm.assume(o != user);
        Acct memory u0 = _a(user);
        Acct memory b0 = _a(bridge);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();
        lim0 = _bt().burningCurrentLimitOf(bridge);
        uint256 max0 = _bt().burningMaxLimitOf(bridge);

        alx = t.allowance(user, bridge);
        _framePick();
        vm.assume(ao != user || asp != bridge);
        bool ok = _call(bridge, abi.encodeCall(BridgedEnforcedToken.burn, (user, amt)));
        if (!ok) return;

        assert(max0 > 0 && amt <= lim0); // allow-listed and within its limit
        assert(b0.st != 2); // a blocked bridge is shut
        assert(u0.st == 0); // FROZEN and BLOCKED holders cannot bridge out (Inv 3)
        assert(amt <= u0.bal - u0.held); // held value cannot leave (Inv 2)
        assert(_a(user).bal == u0.bal - amt && _a(user).held == u0.held && _a(user).st == u0.st);
        assert(t.totalSupply() == s0 - amt); // Inv 4: supply falls with the balance
        (, uint256 cur, uint256 ts) = _bt().rawBurning(bridge);
        assert(cur == lim0 - amt && ts == uint32(block.timestamp)); // the limit is consumed
        assert(_wf(user));
        assert(t.logCount() == c0);
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0);
        // a bridge other than the holder spends the holder's allowance exactly like transferFrom
        if (bridge == user || alx == type(uint256).max) assert(t.allowance(user, bridge) == alx);
        else assert(amt <= alx && t.allowance(user, bridge) == alx - amt);
        assert(_frameSame()); // no other allowance or custody entry changes
    }

    // ============================================================ B2: bridge-in
    function check_bridgeMint(address bridge, address to, uint256 amt, address o, bytes32 id2) public {
        vm.assume(bridge != address(this)); // not the minter: a bridge
        vm.assume(_wf(to) && o != to);
        Acct memory t0 = _a(to);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();
        lim0 = _bt().mintingCurrentLimitOf(bridge);
        uint256 max0 = _bt().mintingMaxLimitOf(bridge);
        uint8 bst0 = t.statusOf(bridge);

        _framePick();
        bool ok = _call(bridge, abi.encodeCall(EnforcedToken.mint, (to, amt)));
        if (!ok) return;

        assert(max0 > 0 && amt <= lim0);
        assert(bst0 != 2); // a BLOCKED bridge cannot mint
        assert(t0.st != 2); // never to a BLOCKED account
        assert(_a(to).bal == t0.bal + amt && _a(to).held == t0.held && _a(to).st == t0.st);
        assert(t.totalSupply() == s0 + amt);
        (, uint256 cur, uint256 ts) = _bt().rawMinting(bridge);
        assert(cur == lim0 - amt && ts == uint32(block.timestamp)); // the limit is consumed
        assert(_wf(to));
        assert(t.logCount() == c0);
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0);
        assert(_frameSame()); // no allowance or custody entry changes
    }

    // ============================================================ B3: limits
    function check_setLimits(address caller, address bridge, uint256 m, uint256 u, bytes32 ev, address o) public {
        Acct memory o0 = _a(o);
        s0 = t.totalSupply();
        c0 = t.logCount();
        bytes32 h0 = t.logHead();
        _framePick();
        bool ok = _call(caller, abi.encodeCall(BridgedEnforcedToken.setLimits, (bridge, m, u, ev)));
        if (!ok) return;
        assert(caller == AUTH);
        assert(_bt().mintingMaxLimitOf(bridge) == m && _bt().burningMaxLimitOf(bridge) == u);
        (, uint256 mc,) = _bt().rawMinting(bridge);
        (, uint256 bc,) = _bt().rawBurning(bridge);
        assert(mc <= m && bc <= u); // available value stays within the new maxima
        assert(t.logCount() == c0 + 1);
        assert(t.logHead() == keccak256(abi.encode(h0, c0, uint8(7), keccak256(abi.encode(bridge, m, u)), ev)));
        assert(t.totalSupply() == s0);
        assert(_same(_a(o), o0));
        assert(_frameSame()); // no allowance or custody entry changes
    }
}
