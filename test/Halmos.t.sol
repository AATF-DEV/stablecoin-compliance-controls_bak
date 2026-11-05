// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";

/// Symbolic proofs for EnforcedToken (run with `halmos --contract HalmosProofs`).
///
/// Method: the token's entire storage is made symbolic, so every check quantifies over
/// ALL contract states, not just reachable-by-fuzzing ones. Each check assumes the
/// invariant for the accounts the call touches, executes one public function with
/// symbolic arguments and caller, and asserts that the invariant still holds and that
/// the state changed exactly as specified. Together with the initial state (no balances,
/// holds or log entries; only the deployment's custody list), which satisfies every
/// invariant, this is an inductive proof over all call sequences.
/// An untouched account `o` is checked to be unchanged, which extends per-account
/// statements to all accounts. Allowances are covered the same way: transferFrom spends exactly
/// `amt` of a finite allowance and keeps an infinite one, approve sets exactly one entry, and an
/// arbitrary other allowance entry is unchanged by every call. Likewise for the custody list:
/// seize credits only a custody account, setCustody changes exactly one entry, and an arbitrary
/// other custody entry is unchanged by every call.
contract HalmosProofs is SymTest, Test {
    EnforcedToken t;
    address constant AUTH = address(0xA0);
    bytes32 constant EV = keccak256("ev");
    uint256 internal q0;
    uint256 internal s0; // pre-state total supply
    uint256 internal c0; // pre-state log counter // snapshot of an unrelated hold record (kept in storage to limit stack use)
    bytes32 internal hd0; // pre-state log head

    struct Acct {
        uint256 bal;
        uint256 held;
        uint8 st;
    }

    function setUp() public virtual {
        t = new EnforcedToken(AUTH, new address[](0)); // minter = this
        svm.enableSymbolicStorage(address(t));
    }

    // ------------------------------------------------------------ helpers
    function _a(address x) internal view returns (Acct memory r) {
        r.bal = t.balanceOf(x);
        r.held = t.heldOf(x);
        r.st = t.statusOf(x);
    }

    /// well-formed account: held <= balance, valid status (Invariant 2 hypothesis)
    function _wf(address x) internal view returns (bool) {
        Acct memory r = _a(x);
        return r.held <= r.bal && r.st <= 2;
    }

    function _same(Acct memory x, Acct memory y) internal pure returns (bool) {
        return x.bal == y.bal && x.held == y.held && x.st == y.st;
    }

    /// frame condition on an arbitrary other hold record
    function _holdSnap(bytes32 id2) internal view returns (uint256) {
        (address a, uint96 v) = t.holds(id2);
        return (uint256(uint160(a)) << 96) | v; // exact packing, injective
    }

    /// Inv 6: exactly one entry was appended and the head is the specified hash of it.
    function _logged(uint8 action, bytes32 paramsHash, bytes32 ev) internal view returns (bool) {
        return t.logCount() == c0 + 1 && t.logHead() == keccak256(abi.encode(hd0, c0, action, paramsHash, ev));
    }

    /// frame conditions on an arbitrary allowance entry (owner `ao`, spender `asp`) and an
    /// arbitrary custody-list entry `cu`
    address internal ao;
    address internal asp;
    uint256 internal al0; // its pre-state value
    uint256 internal alx; // pre-state value of the entry a call is allowed to change
    address internal cu;
    bool internal cu0;

    function _framePick() internal {
        ao = svm.createAddress("allowOwner");
        asp = svm.createAddress("allowSpender");
        al0 = t.allowance(ao, asp);
        cu = svm.createAddress("custody");
        cu0 = t.isCustody(cu);
    }

    function _frameSame() internal view returns (bool) {
        return t.allowance(ao, asp) == al0 && t.isCustody(cu) == cu0;
    }

    function _call(address caller, bytes memory data) internal returns (bool ok) {
        vm.prank(caller);
        (ok,) = address(t).call(data);
    }

    // ============================================================ transfers (Inv 2, 3, 4)
    function check_transfer(address from, address to, uint256 amt, address o, bytes32 id2) public {
        vm.assume(_wf(from) && _wf(to));
        vm.assume(o != from && o != to);
        Acct memory f0 = _a(from);
        Acct memory t0 = _a(to);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();

        _framePick();
        bool ok = _call(from, abi.encodeCall(EnforcedToken.transfer, (to, amt)));
        if (!ok) return;

        // Inv 3: only an ACTIVE sender can move funds; a BLOCKED recipient never receives
        assert(f0.st == 0);
        assert(t0.st != 2);
        // spendable-balance check
        assert(amt <= f0.bal - f0.held);
        // exact effect, supply conservation (Inv 4)
        Acct memory f1 = _a(from);
        Acct memory t1 = _a(to);
        if (from != to) {
            assert(f1.bal == f0.bal - amt && t1.bal == t0.bal + amt);
        } else {
            assert(f1.bal == f0.bal);
        }
        assert(f1.held == f0.held && t1.held == t0.held && f1.st == f0.st && t1.st == t0.st);
        assert(t.totalSupply() == s0);
        // Inv 2 preserved; frame condition
        assert(_wf(from) && _wf(to));
        assert(t.logCount() == c0); // Inv 6: non-compliance calls never touch the log
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        assert(_frameSame()); // no allowance or custody entry changes
    }

    function check_transferFrom(address spender, address from, address to, uint256 amt, address o, bytes32 id2) public {
        vm.assume(_wf(from) && _wf(to) && _wf(spender));
        vm.assume(o != from && o != to && o != spender);
        Acct memory f0 = _a(from);
        Acct memory t0 = _a(to);
        Acct memory sp0 = _a(spender);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();

        alx = t.allowance(from, spender);
        _framePick();
        vm.assume(ao != from || asp != spender);
        bool ok = _call(spender, abi.encodeCall(EnforcedToken.transferFrom, (from, to, amt)));
        if (!ok) return;

        assert(sp0.st != 2); // a blocked spender cannot move third-party funds
        assert(f0.st == 0);
        assert(t0.st != 2);
        assert(amt <= f0.bal - f0.held);
        if (from != to) assert(_a(from).bal == f0.bal - amt && _a(to).bal == t0.bal + amt);
        assert(t.totalSupply() == s0);
        assert(_wf(from) && _wf(to));
        assert(t.logCount() == c0); // Inv 6: non-compliance calls never touch the log
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        // allowance: an infinite allowance is kept, a finite one is spent by exactly `amt`
        if (alx == type(uint256).max) assert(t.allowance(from, spender) == alx);
        else assert(amt <= alx && t.allowance(from, spender) == alx - amt);
        assert(_frameSame()); // no other allowance or custody entry changes
    }

    function check_mint(address to, uint256 amt, address o, bytes32 id2) public {
        vm.assume(_wf(to) && o != to);
        Acct memory t0 = _a(to);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();
        _framePick();
        bool ok = _call(address(this), abi.encodeCall(EnforcedToken.mint, (to, amt)));
        if (!ok) return;
        assert(t0.st != 2);
        assert(_a(to).bal == t0.bal + amt && _a(to).held == t0.held);
        assert(t.totalSupply() == s0 + amt); // Inv 4: supply moves with balances
        assert(_wf(to));
        assert(t.logCount() == c0); // Inv 6: non-compliance calls never touch the log
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        assert(_frameSame()); // no allowance or custody entry changes
    }

    // ============================================================ holds (Inv 1, 2, 4)
    function check_placeHold(bytes32 id, address a, uint96 amt, bytes32 ev, address o, bytes32 id2) public {
        vm.assume(id2 != id);
        vm.assume(_wf(a) && o != a);
        Acct memory a0 = _a(a);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        (address h0a,) = t.holds(id);
        s0 = t.totalSupply();
        c0 = t.logCount();
        hd0 = t.logHead();

        _framePick();
        bool ok = _call(AUTH, abi.encodeCall(EnforcedToken.placeHold, (id, a, amt, ev)));
        if (!ok) return;

        assert(h0a == address(0)); // a hold id is never reused while active
        assert(amt <= a0.bal - a0.held); // only spendable value can be held
        (address h1a, uint96 h1v) = t.holds(id);
        assert(h1a == a && h1v == amt);
        // Inv 2 bookkeeping: held increases by exactly the new hold
        assert(_a(a).held == a0.held + amt && _a(a).bal == a0.bal && _a(a).st == a0.st);
        assert(t.totalSupply() == s0);
        assert(_logged(2, keccak256(abi.encode(id, a, amt)), ev)); // Inv 6
        assert(_wf(a));
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        assert(_frameSame()); // no allowance or custody entry changes
    }

    /// Hypothesis for hold-consuming actions: the hold is backed by the account's held amount.
    function _holdBacked(bytes32 id) internal view returns (address a, uint96 v) {
        (a, v) = t.holds(id);
        vm.assume(a != address(0));
        vm.assume(_wf(a));
        vm.assume(v <= t.heldOf(a));
    }

    function check_releaseHold(bytes32 id, bytes32 ev, address o, bytes32 id2) public {
        vm.assume(id2 != id);
        (address a, uint96 v) = _holdBacked(id);
        vm.assume(o != a);
        Acct memory a0 = _a(a);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        c0 = t.logCount();
        hd0 = t.logHead();
        s0 = t.totalSupply();

        _framePick();
        bool ok = _call(AUTH, abi.encodeCall(EnforcedToken.releaseHold, (id, ev)));
        if (!ok) return;

        (address h1a,) = t.holds(id);
        assert(h1a == address(0));
        assert(_a(a).held == a0.held - v && _a(a).bal == a0.bal);
        assert(_logged(3, keccak256(abi.encode(id)), ev)); // Inv 6
        assert(_wf(a));
        assert(t.totalSupply() == s0); // Inv 4
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        assert(_frameSame()); // no allowance or custody entry changes
    }

    function check_seize(bytes32 id, uint96 amt, address dest, bytes32 ev, address o, bytes32 id2) public {
        vm.assume(id2 != id);
        (address a, uint96 v) = _holdBacked(id);
        vm.assume(_wf(dest));
        vm.assume(o != a && o != dest);
        Acct memory a0 = _a(a);
        Acct memory d0 = _a(dest);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();

        hd0 = t.logHead();
        _framePick();
        bool ok = _call(AUTH, abi.encodeCall(EnforcedToken.seize, (id, amt, dest, ev)));
        if (!ok) return;

        // Inv 1: only value under this hold is taken, and exactly that much leaves `held`
        assert(amt <= v);
        assert(_a(a).held == a0.held - amt);
        (, uint96 v1) = t.holds(id);
        assert(v1 == v - amt);
        assert(t.isCustody(dest)); // only a designated custody account receives seized value
        assert(d0.st != 2);
        if (dest != a) {
            assert(_a(a).bal == a0.bal - amt && _a(dest).bal == d0.bal + amt);
        } else {
            assert(_a(a).bal == a0.bal);
        }
        assert(t.totalSupply() == s0); // seizure is supply-neutral
        assert(_logged(4, keccak256(abi.encode(id, amt, dest)), ev)); // Inv 6
        assert(_wf(a) && _wf(dest));
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        assert(_frameSame()); // no allowance or custody entry changes
    }

    function check_burnFromHold(bytes32 id, uint96 amt, bytes32 ev, address o, bytes32 id2) public {
        vm.assume(id2 != id);
        (address a, uint96 v) = _holdBacked(id);
        vm.assume(o != a);
        Acct memory a0 = _a(a);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();

        hd0 = t.logHead();
        _framePick();
        bool ok = _call(AUTH, abi.encodeCall(EnforcedToken.burnFromHold, (id, amt, ev)));
        if (!ok) return;

        assert(amt <= v); // Inv 1
        assert(_a(a).held == a0.held - amt && _a(a).bal == a0.bal - amt);
        (, uint96 v1) = t.holds(id);
        assert(v1 == v - amt);
        assert(t.totalSupply() == s0 - amt); // Inv 4: supply falls by exactly the burn
        assert(_logged(5, keccak256(abi.encode(id, amt)), ev)); // Inv 6
        assert(_wf(a));
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        assert(_frameSame()); // no allowance or custody entry changes
    }

    // ============================================================ status, log (Inv 2, 6)
    function check_setStatus(address a, uint8 s, bytes32 ev, address o, bytes32 id2) public {
        vm.assume(_wf(a) && o != a);
        Acct memory a0 = _a(a);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        bytes32 h0 = t.logHead();
        c0 = t.logCount();
        s0 = t.totalSupply();

        _framePick();
        bool ok = _call(AUTH, abi.encodeCall(EnforcedToken.setStatus, (a, s, ev)));
        if (!ok) return;

        assert(s <= 2);
        assert(_a(a).st == s && _a(a).bal == a0.bal && _a(a).held == a0.held);
        // Inv 6: exactly one chained entry, with the specified hash
        assert(t.logCount() == c0 + 1);
        assert(t.logHead() == keccak256(abi.encode(h0, c0, uint8(1), keccak256(abi.encode(a, s)), ev)));
        assert(_wf(a));
        assert(t.totalSupply() == s0); // Inv 4
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0); // no other hold record changes
        assert(_frameSame()); // no allowance or custody entry changes
    }

    /// Batch of up to two addresses (halmos default array bound). Balances, held amounts and
    /// supply are unchanged; every listed account ends BLOCKED; an unlisted account and an
    /// unrelated hold record are untouched; exactly one log entry is appended.
    function check_blockBatch(address x0, address x1, bool two, bytes32 ev, address o, bytes32 id2) public {
        vm.assume(_wf(x0) && _wf(x1));
        vm.assume(o != x0 && o != x1);
        address[] memory xs = new address[](two ? 2 : 1);
        xs[0] = x0;
        if (two) xs[1] = x1;
        Acct memory a0 = _a(x0);
        Acct memory a1 = _a(x1);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();

        hd0 = t.logHead();
        _framePick();
        bool ok = _call(AUTH, abi.encodeCall(EnforcedToken.blockBatch, (xs, ev)));
        if (!ok) return;

        assert(t.statusOf(x0) == 2);
        assert(_a(x0).bal == a0.bal && _a(x0).held == a0.held);
        if (two) {
            assert(t.statusOf(x1) == 2);
            assert(_a(x1).bal == a1.bal && _a(x1).held == a1.held);
        } else if (x1 != x0) {
            assert(_same(_a(x1), a1));
        }
        assert(t.totalSupply() == s0);
        assert(_logged(6, keccak256(abi.encodePacked(xs)), ev)); // Inv 6
        assert(_wf(x0) && _wf(x1));
        assert(_same(_a(o), o0));
        assert(_holdSnap(id2) == q0);
        assert(_frameSame()); // no allowance or custody entry changes
    }

    /// approve changes exactly one allowance entry: no account, hold, supply or log state moves.
    function check_approve(address owner, address spender, uint256 amt, address o, bytes32 id2) public {
        Acct memory w0 = _a(owner);
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();
        bytes32 h0 = t.logHead();
        _framePick();
        vm.assume(ao != owner || asp != spender);
        bool ok = _call(owner, abi.encodeCall(EnforcedToken.approve, (spender, amt)));
        if (!ok) return;
        assert(t.allowance(owner, spender) == amt);
        assert(_same(_a(owner), w0) && _same(_a(o), o0));
        assert(_holdSnap(id2) == q0);
        assert(t.totalSupply() == s0 && t.logCount() == c0 && t.logHead() == h0);
        assert(_frameSame()); // no other allowance or custody entry changes
    }

    /// Only the minter can mint; any other caller leaves all state unchanged (reverts).
    function check_mintOnlyMinter(address caller, address to, uint256 amt) public virtual {
        vm.assume(caller != address(this));
        assert(!_call(caller, abi.encodeCall(EnforcedToken.mint, (to, amt))));
    }

    function _one(address a) internal pure returns (address[] memory xs) {
        xs = new address[](1);
        xs[0] = a;
    }

    // ============================================================ custody list
    /// setCustody changes exactly one custody entry (never for address 0) and appends exactly one
    /// log entry; no account, hold, supply or allowance changes.
    function check_setCustody(address a, bool allowed, bytes32 ev, address o, bytes32 id2) public {
        Acct memory o0 = _a(o);
        q0 = _holdSnap(id2);
        s0 = t.totalSupply();
        c0 = t.logCount();
        hd0 = t.logHead();
        _framePick();
        vm.assume(cu != a);
        bool ok = _call(AUTH, abi.encodeCall(EnforcedToken.setCustody, (a, allowed, ev)));
        if (!ok) return;
        assert(a != address(0));
        assert(t.isCustody(a) == allowed);
        assert(_logged(8, keccak256(abi.encode(a, allowed)), ev)); // Inv 6
        assert(t.totalSupply() == s0);
        assert(_same(_a(o), o0)); // o may equal a: custody status is not account state
        assert(_holdSnap(id2) == q0);
        assert(_frameSame()); // no allowance or other custody entry changes
    }

    // ============================================================ authority gate (Inv 5, token side)
    /// No caller other than the authority can change compliance state, through any function.
    function check_onlyAuthority(address caller, bytes4 sel, bytes32 id, address a, uint96 amt, uint8 s, bytes32 ev)
        public
    {
        vm.assume(caller != AUTH);
        bytes memory data;
        if (sel == EnforcedToken.setStatus.selector) data = abi.encodeCall(EnforcedToken.setStatus, (a, s, ev));
        else if (sel == EnforcedToken.placeHold.selector) data = abi.encodeCall(EnforcedToken.placeHold, (id, a, amt, ev));
        else if (sel == EnforcedToken.releaseHold.selector) data = abi.encodeCall(EnforcedToken.releaseHold, (id, ev));
        else if (sel == EnforcedToken.seize.selector) data = abi.encodeCall(EnforcedToken.seize, (id, amt, a, ev));
        else if (sel == EnforcedToken.burnFromHold.selector) data = abi.encodeCall(EnforcedToken.burnFromHold, (id, amt, ev));
        else if (sel == EnforcedToken.blockBatch.selector) data = abi.encodeCall(EnforcedToken.blockBatch, (_one(a), ev));
        else if (sel == EnforcedToken.setCustody.selector) data = abi.encodeCall(EnforcedToken.setCustody, (a, s == 0, ev));
        else return;
        assert(!_call(caller, data));
    }
}
