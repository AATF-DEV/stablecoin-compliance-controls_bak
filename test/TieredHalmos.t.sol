// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";
import {TieredAuthority} from "../src/TieredAuthority.sol";
import {BridgedEnforcedToken} from "../src/BridgedEnforcedToken.sol";

/// ecrecover abstracted: the i-th recovered address is an arbitrary (symbolic) storage value,
/// so every check below holds for every possible outcome of signature recovery.
contract TieredHarness is TieredAuthority {
    mapping(uint256 => address) public fakeRec;

    constructor(
        address[] memory s,
        uint8[] memory r,
        bytes32[] memory att,
        address[] memory g,
        TieredAuthority.Policy memory p
    ) TieredAuthority(s, r, att, g, p) {}

    function _recover(bytes32, bytes calldata, uint256 i) internal view override returns (address) {
        return fakeRec[i];
    }
}

/// Accepts any call; used as the target of payload-independent slow-tier checks.
contract Sink {
    fallback() external payable {}
}

/// Symbolic proofs for TieredAuthority (run with `halmos --contract TieredProofs`).
///
/// The storage of both the authority and the token is symbolic (including every slot the
/// constructor wrote, see setUp), so the checks quantify over all authority configurations
/// (signers, roles, guardians, policy, budgets, queue), all token states, and every outcome of
/// signature recovery.
///
///   T1  The fast tier only restricts: it never lowers a status, never reduces a held amount,
///       never moves a balance, never touches an existing hold, never raises a bridge limit,
///       never adds a custody account, never queues, and only runs with at least M_r approvals
///       and within the restriction budget, which is charged one unit per restrained account (one
///       per address of a blockBatch); the approvers cover at least rolesR distinct roles.
///   T2  The fast tier rejects every other target and every non-restrictive selector.
///   T3  Queuing needs at least M_i approvals covering at least rolesI distinct roles, and sets
///       eta = now + delay.
///   T4  A queued action executes once, only in [eta, eta + GRACE].
///   T5  A cancelled action can never execute; cancelling needs the guardian quorum.
///   T6  Seized plus burned value never exceeds the per-epoch value budget, whatever the target
///       (the bound token, a token not yet bound, or any other contract).
///   T7  Configuration changes only through the authority itself (i.e. the slow tier), and every
///       change leaves a policy with 1 <= M_r < M_i <= N, roles coverable, a non-empty guardian
///       quorum and delay >= MIN_DELAY; signers and guardians stay disjoint; and the counters
///       behind these bounds (signers, roles, guardians) change exactly with the membership.
contract TieredProofs is SymTest, Test {
    TieredHarness a;
    BridgedEnforcedToken t; // superset of EnforcedToken: also covers bridge-limit actions
    Sink sink;

    // pre-state snapshots (storage, to keep the stack small)
    uint256 s0;
    uint256 n0;
    uint256 e0;
    uint8 st0;
    uint256 held0;
    uint256 bal0;
    uint256 q0;
    uint256 qe0;
    uint256 mmax0;
    uint256 bmax0;
    uint256 ei0; // pre-state budget epoch index
    uint256 ru0; // pre-state restricted count
    uint256 rq0; // pre-state role requirement
    bool cust0; // pre-state custody flag of `o`

    function setUp() public {
        address[] memory s = new address[](3);
        uint8[] memory r = new uint8[](3);
        bytes32[] memory att = new bytes32[](3);
        for (uint256 i; i < 3; ++i) {
            s[i] = address(uint160(0x5000 + i));
            r[i] = uint8(i);
        }
        address[] memory g = new address[](1);
        g[0] = address(0x6000);
        a = new TieredHarness(
            s,
            r,
            att,
            g,
            TieredAuthority.Policy({
                mR: 1, mI: 2, rolesR: 1, rolesI: 2, gThreshold: 1, delay: 1 hours, epoch: 1 days, restrictBudget: 10,
                valueBudget: 100
            })
        );
        t = new BridgedEnforcedToken(address(a), new address[](0));
        sink = new Sink();
        svm.enableSymbolicStorage(address(a));
        svm.enableSymbolicStorage(address(t));
        // enableSymbolicStorage only affects slots that were never written. Every slot the
        // constructor wrote is overwritten here with a fresh symbolic value, so the checks do
        // not depend on the setUp configuration. Slots follow `forge inspect TieredHarness
        // storageLayout`: 1 policy, 4 signers, 5 signerCount, 6 _roleCount, 7 distinctRoles,
        // 8 isGuardian, 9 guardianCount.
        _sym(bytes32(uint256(1)), "policy");
        _sym(bytes32(uint256(5)), "signerCount");
        _sym(bytes32(uint256(7)), "distinctRoles");
        _sym(bytes32(uint256(9)), "guardianCount");
        for (uint256 i; i < 3; ++i) {
            bytes32 base = keccak256(abi.encode(address(uint160(0x5000 + i)), uint256(4)));
            _sym(base, "signer.word0");
            _sym(bytes32(uint256(base) + 1), "signer.attestation");
            _sym(keccak256(abi.encode(i, uint256(6))), "roleCount");
        }
        _sym(keccak256(abi.encode(address(0x6000), uint256(8))), "isGuardian");
    }

    function _sym(bytes32 slot, string memory name) internal {
        vm.store(address(a), slot, svm.createBytes32(name));
    }

    // ------------------------------------------------------------ helpers
    /// k in {1,2,3} signatures; branching keeps the byte length concrete on every path.
    /// Contents are irrelevant: recovery is abstracted.
    function _sigs(uint256 k) internal pure returns (bytes memory) {
        if (k == 1) return new bytes(65);
        if (k == 2) return new bytes(130);
        return new bytes(195);
    }

    function _holdSnap(bytes32 id) internal view returns (uint256) {
        (address h, uint96 v) = t.holds(id);
        return (uint256(uint160(h)) << 96) | v;
    }

    function _mR() internal view returns (uint256 m) {
        (m,,,,,,,,) = a.policy();
    }

    function _mI() internal view returns (uint256 m) {
        (, m,,,,,,,) = a.policy();
    }

    function _delay() internal view returns (uint256 d) {
        (,,,,, d,,,) = a.policy();
    }

    function _gThreshold() internal view returns (uint256 g) {
        (,,,, g,,,,) = a.policy();
    }

    function _budgets() internal view returns (uint256 rb, uint256 vb) {
        (,,,,,,, rb, vb) = a.policy();
    }

    function _used() internal view returns (uint256 r, uint256 v) {
        (, r, v) = a.usage();
    }

    function _epoch() internal view returns (uint256 e) {
        (,,,,,, e,,) = a.policy();
    }

    function _rolesR() internal view returns (uint256 r) {
        (,, r,,,,,,) = a.policy();
    }

    function _rolesI() internal view returns (uint256 r) {
        (,,, r,,,,,) = a.policy();
    }

    /// Number of distinct roles (valid roles are < MAX_ROLES = 8) among the first k recovered
    /// approvers. Written out case by case, independently of the contract's bit-mask popcount.
    function _distinctRoles(uint256 k) internal view returns (uint256 n) {
        (, uint8 r0,) = a.signers(a.fakeRec(0));
        bool v0 = r0 < 8;
        n = v0 ? 1 : 0;
        if (k < 2) return n;
        (, uint8 r1,) = a.signers(a.fakeRec(1));
        bool v1 = r1 < 8 && !(v0 && r1 == r0);
        if (v1) n += 1;
        if (k < 3) return n;
        (, uint8 r2,) = a.signers(a.fakeRec(2));
        if (r2 < 8 && !(r2 < 8 && v0 && r2 == r0) && !(r1 < 8 && r2 == r1)) n += 1;
    }

    function _fastData(uint8 which, address x, address y, uint8 s, bytes32 hid, uint96 amt, address dest, bytes32 ev)
        internal
        pure
        returns (bytes memory)
    {
        if (which == 0) return abi.encodeCall(EnforcedToken.setStatus, (x, s, ev));
        if (which == 1 || which == 2) {
            address[] memory xs = new address[](which);
            xs[0] = x;
            if (which == 2) xs[1] = y;
            return abi.encodeCall(EnforcedToken.blockBatch, (xs, ev));
        }
        if (which == 3) return abi.encodeCall(EnforcedToken.placeHold, (hid, x, amt, ev));
        if (which == 4) return abi.encodeCall(EnforcedToken.releaseHold, (hid, ev));
        if (which == 5) return abi.encodeCall(EnforcedToken.seize, (hid, amt, dest, ev));
        if (which == 6) return abi.encodeCall(EnforcedToken.burnFromHold, (hid, amt, ev));
        return abi.encodeCall(EnforcedToken.setCustody, (x, s == 0, ev)); // add (s == 0) or remove
    }

    // ============================================================ T1: the fast tier only restricts
    bytes32 id2; // an arbitrary existing hold record
    bytes32 qid; // an arbitrary queue slot

    function _fastDataSym(uint8 which, address x, address y) internal returns (bytes memory) {
        return _fastData(
            which,
            x,
            y,
            uint8(svm.createUint(8, "s")),
            svm.createBytes32("hid"),
            uint96(svm.createUint(96, "amt")),
            svm.createAddress("dest"),
            svm.createBytes32("ev")
        );
    }

    function check_fastOnlyRestricts(uint8 which, address x, address y, uint8 k, address o) public {
        vm.assume(a.token() == address(t));
        vm.assume(which <= 7 && k >= 1 && k <= 3);
        vm.assume(t.statusOf(x) <= 2 && t.statusOf(y) <= 2 && t.statusOf(o) <= 2); // well-formed statuses
        bytes memory data = _fastDataSym(which, x, y);
        id2 = svm.createBytes32("id2");
        qid = svm.createBytes32("qid");

        st0 = t.statusOf(o);
        held0 = t.heldOf(o);
        bal0 = t.balanceOf(o);
        s0 = t.totalSupply();
        q0 = _holdSnap(id2);
        qe0 = a.eta(qid);
        n0 = a.nonce();
        mmax0 = t.mintingMaxLimitOf(o);
        bmax0 = t.burningMaxLimitOf(o);
        cust0 = t.isCustody(o);
        (uint64 e64, uint32 r32,) = a.usage();
        (ei0, ru0) = (e64, r32);
        rq0 = _rolesR();

        (bool ok,) = address(a).call(
            abi.encodeCall(
                TieredAuthority.execute,
                (address(t), data, svm.createBytes32("ev2"), svm.createUint256("deadline"), _sigs(k))
            )
        );
        if (!ok) return;

        assert(which <= 3 || which == 7); // release, seize and burn never pass the fast tier
        assert(cust0 || !t.isCustody(o)); // no seizure destination is ever added
        assert(t.mintingMaxLimitOf(o) == mmax0 && t.burningMaxLimitOf(o) == bmax0); // limits untouched
        assert(t.statusOf(o) >= st0); // restriction only goes up
        assert(t.heldOf(o) >= held0); // nothing is released or debited
        assert(t.balanceOf(o) == bal0); // no value moves
        assert(t.totalSupply() == s0);
        if (q0 >> 96 != 0) assert(_holdSnap(id2) == q0); // existing holds untouched
        assert(a.eta(qid) == qe0); // nothing queued or dequeued
        assert(a.nonce() == n0 + 1);
        assert(k >= _mR());
        assert(_distinctRoles(k) >= rq0); // the approvers cover at least rolesR roles
        (uint256 rb,) = _budgets();
        (uint256 ru,) = _used();
        assert(ru <= rb);
        // every restrained account is charged: setStatus and placeHold count one account,
        // blockBatch one per address (the budget counter is reset at an epoch boundary)
        uint256 w = which == 2 ? 2 : 1;
        uint256 e = block.timestamp / _epoch();
        assert(ru == (ei0 == e ? ru0 + w : w));
    }

    /// T1 for bridge limits: through the fast tier a limit can only be lowered (e.g. to shut a
    /// compromised bridge), never raised; no status, hold, balance or supply changes. The number
    /// of signatures is fixed at 2 here (the quorum itself is covered by check_fastOnlyRestricts
    /// for every k), which keeps the limit arithmetic tractable.
    function check_fastBridgeLimits(address bridge, address o) public {
        vm.assume(a.token() == address(t));
        bytes memory data = abi.encodeCall(
            BridgedEnforcedToken.setLimits,
            (bridge, svm.createUint256("mintLimit"), svm.createUint256("burnLimit"), svm.createBytes32("ev"))
        );
        mmax0 = t.mintingMaxLimitOf(o);
        bmax0 = t.burningMaxLimitOf(o);
        st0 = t.statusOf(o);
        held0 = t.heldOf(o);
        bal0 = t.balanceOf(o);
        s0 = t.totalSupply();
        (bool ok,) = address(a).call(
            abi.encodeCall(
                TieredAuthority.execute,
                (address(t), data, svm.createBytes32("ev2"), svm.createUint256("deadline"), _sigs(2))
            )
        );
        if (!ok) return;
        assert(t.mintingMaxLimitOf(o) <= mmax0 && t.burningMaxLimitOf(o) <= bmax0);
        assert(t.statusOf(o) == st0 && t.heldOf(o) == held0 && t.balanceOf(o) == bal0 && t.totalSupply() == s0);
    }

    // ============================================================ T2: fast tier fails closed
    function check_fastRejectsOthers(address target, bytes4 sel, bytes32 w1, bytes32 w2, bytes32 ev, uint8 k) public {
        vm.assume(k >= 1 && k <= 3);
        bool restrictiveSel = sel == EnforcedToken.setStatus.selector || sel == EnforcedToken.blockBatch.selector
            || sel == EnforcedToken.placeHold.selector || sel == BridgedEnforcedToken.setLimits.selector
            || sel == EnforcedToken.setCustody.selector;
        vm.assume(target != a.token() || !restrictiveSel);
        bytes memory data = abi.encodePacked(sel, w1, w2, ev);
        (bool ok,) =
            address(a).call(abi.encodeCall(TieredAuthority.execute, (target, data, ev, type(uint256).max, _sigs(k))));
        assert(!ok);
    }

    // ============================================================ T3: queuing
    function check_queue(bytes32 w, bytes32 ev, uint256 deadline, uint8 k, uint256 ts) public {
        vm.assume(k >= 1 && k <= 3);
        vm.warp(ts);
        bytes memory data = abi.encodePacked(w);
        n0 = a.nonce();
        bytes32 id = a.digest(address(sink), data, ev, n0, deadline);
        (bool ok,) = address(a).call(abi.encodeCall(TieredAuthority.queue, (address(sink), data, ev, deadline, _sigs(k))));
        if (!ok) return;
        assert(k >= _mI());
        assert(_distinctRoles(k) >= _rolesI()); // the approvers cover at least rolesI roles
        assert(a.eta(id) == ts + _delay());
        assert(a.nonce() == n0 + 1);
    }

    // ============================================================ T4: execution window, once
    function check_executeQueued(bytes32 w, bytes32 ev, uint256 n, uint256 deadline, uint256 ts) public {
        bytes memory data = abi.encodePacked(w);
        bytes32 id = a.digest(address(sink), data, ev, n, deadline);
        e0 = a.eta(id);
        n0 = a.nonce();
        vm.warp(ts);
        (bool ok,) =
            address(a).call(abi.encodeCall(TieredAuthority.executeQueued, (address(sink), data, ev, n, deadline)));
        if (!ok) return;
        assert(e0 != 0);
        assert(ts >= e0 && ts <= e0 + a.GRACE());
        assert(a.eta(id) == 0); // consumed: cannot execute twice
        assert(a.nonce() == n0);
    }

    // ============================================================ T5: cancellation is final
    function check_cancel(bytes32 w, bytes32 ev, uint256 n, uint256 deadline, uint8 k, uint256 ts) public {
        vm.assume(k >= 1 && k <= 3);
        bytes memory data = abi.encodePacked(w);
        bytes32 id = a.digest(address(sink), data, ev, n, deadline);
        (bool ok,) = address(a).call(abi.encodeCall(TieredAuthority.cancel, (id, _sigs(k))));
        if (!ok) return;
        assert(k >= _gThreshold());
        assert(a.eta(id) == 0);
        vm.warp(ts);
        (bool ran,) =
            address(a).call(abi.encodeCall(TieredAuthority.executeQueued, (address(sink), data, ev, n, deadline)));
        assert(!ran);
    }

    // ============================================================ T6: value budget
    /// Holds for the bound token, for a token that is not (yet) bound, and for any other target
    /// (`other` sends the same calldata to an unrelated contract).
    function check_valueBudget(
        bool burn,
        bool other,
        bytes32 hid,
        uint96 amt,
        address dest,
        bytes32 ev,
        uint256 n,
        uint256 deadline
    ) public {
        bytes memory data = burn
            ? abi.encodeCall(EnforcedToken.burnFromHold, (hid, amt, ev))
            : abi.encodeCall(EnforcedToken.seize, (hid, amt, dest, ev));
        address target = other ? address(sink) : address(t);
        (bool ok,) = address(a).call(abi.encodeCall(TieredAuthority.executeQueued, (target, data, ev, n, deadline)));
        if (!ok) return;
        (, uint256 vb) = _budgets();
        (, uint256 vu) = _used();
        assert(vu <= vb);
        assert(vu >= amt); // the debited value was counted
    }

    // ============================================================ T7: configuration
    function _configData(uint8 which, address x, uint8 role, bytes32 att) internal returns (bytes memory) {
        if (which == 0) return abi.encodeCall(TieredAuthority.addSigner, (x, role, att));
        if (which == 1) return abi.encodeCall(TieredAuthority.removeSigner, (x));
        if (which == 2) return abi.encodeCall(TieredAuthority.addGuardian, (x));
        if (which == 3) return abi.encodeCall(TieredAuthority.removeGuardian, (x));
        TieredAuthority.Policy memory p = TieredAuthority.Policy({
            mR: uint8(svm.createUint(8, "mR")),
            mI: uint8(svm.createUint(8, "mI")),
            rolesR: uint8(svm.createUint(8, "rolesR")),
            rolesI: uint8(svm.createUint(8, "rolesI")),
            gThreshold: uint8(svm.createUint(8, "g")),
            delay: uint32(svm.createUint(32, "delay")),
            epoch: uint32(svm.createUint(32, "epoch")),
            restrictBudget: uint32(svm.createUint(32, "rb")),
            valueBudget: uint96(svm.createUint(96, "vb"))
        });
        return abi.encodeCall(TieredAuthority.setPolicy, (p));
    }

    function check_configOnlySelf(address caller, uint8 which, address x, uint8 role, bytes32 att) public {
        vm.assume(caller != address(a) && which <= 4);
        bytes memory data = _configData(which, x, role, att);
        vm.prank(caller);
        (bool ok,) = address(a).call(data);
        assert(!ok);
    }

    function check_configKeepsPolicy(uint8 which, address x, uint8 role, bytes32 att) public {
        vm.assume(which <= 4);
        bytes memory data = _configData(which, x, role, att);
        vm.prank(address(a)); // a self-call, i.e. an executed slow-tier action
        (bool ok,) = address(a).call(data);
        if (!ok) return;
        (uint8 mR, uint8 mI, uint8 rolesR, uint8 rolesI, uint8 g, uint32 delay, uint32 epoch,,) = a.policy();
        assert(mR >= 1 && mR < mI && mI <= a.signerCount());
        assert(rolesR >= 1 && rolesR <= mR && rolesI >= rolesR && rolesI <= mI && rolesI <= a.distinctRoles());
        assert(g >= 1 && g <= a.guardianCount());
        assert(delay >= a.MIN_DELAY() && epoch > 0);
        if (which == 0) {
            (bool active,,) = a.signers(x);
            assert(active && !a.isGuardian(x));
        }
        if (which == 2) {
            (bool active,,) = a.signers(x);
            assert(a.isGuardian(x) && !active);
        }
    }

    // T7 (bookkeeping): the counters that the policy check relies on change exactly with the
    // membership they count. Every configuration change flips at most the membership of the one
    // address it names, and signerCount, _roleCount, distinctRoles and guardianCount move by
    // exactly the matching amount; any other address and any other role count is unchanged.
    // The constructor builds the sets through the same internal functions, so by induction the
    // counters always equal the true sizes, and "1 <= M_r < M_i <= N" etc. refer to real signers.
    uint256 sc0;
    uint256 dr0;
    uint256 gc0;
    uint256 rc0; // role count of the role the call affects
    uint256 rc20; // role count of an unrelated role
    bool xa0;
    uint8 xr0;
    bool xg0;
    bool ya0;
    uint8 yr0;
    bytes32 yat0;
    bool yg0;

    function check_configBookkeeping(uint8 which, address x, uint8 role, bytes32 att, address y, uint256 r2) public {
        vm.assume(which <= 4 && y != x);
        (xa0, xr0,) = a.signers(x);
        xg0 = a.isGuardian(x);
        uint256 affected = which == 0 ? role : xr0;
        vm.assume(r2 != affected);
        (ya0, yr0, yat0) = a.signers(y);
        yg0 = a.isGuardian(y);
        sc0 = a.signerCount();
        dr0 = a.distinctRoles();
        gc0 = a.guardianCount();
        rc0 = a.roleCount(affected);
        rc20 = a.roleCount(r2);

        bytes memory data = _configData(which, x, role, att);
        vm.prank(address(a)); // a self-call, i.e. an executed slow-tier action
        (bool ok,) = address(a).call(data);
        if (!ok) return;

        // frame: nothing else changes
        {
            (bool ya, uint8 yr, bytes32 yat) = a.signers(y);
            assert(ya == ya0 && yr == yr0 && yat == yat0 && a.isGuardian(y) == yg0);
            assert(a.roleCount(r2) == rc20);
        }
        (bool xa, uint8 xr, bytes32 xat) = a.signers(x);
        if (which == 0) {
            // addSigner
            assert(!xa0 && !xg0);
            assert(xa && xr == role && xat == att && !a.isGuardian(x));
            assert(a.signerCount() == sc0 + 1 && a.roleCount(role) == rc0 + 1);
            assert(a.distinctRoles() == dr0 + (rc0 == 0 ? 1 : 0));
            assert(a.guardianCount() == gc0);
        } else if (which == 1) {
            // removeSigner
            assert(xa0 && !xa);
            assert(a.signerCount() == sc0 - 1 && a.roleCount(xr0) == rc0 - 1);
            assert(a.distinctRoles() == dr0 - (rc0 == 1 ? 1 : 0));
            assert(a.guardianCount() == gc0 && a.isGuardian(x) == xg0);
        } else if (which == 2) {
            // addGuardian
            assert(!xg0 && !xa0);
            assert(a.isGuardian(x) && !xa);
            assert(a.guardianCount() == gc0 + 1);
            assert(a.signerCount() == sc0 && a.distinctRoles() == dr0 && a.roleCount(affected) == rc0);
        } else if (which == 3) {
            // removeGuardian
            assert(xg0 && !a.isGuardian(x));
            assert(a.guardianCount() == gc0 - 1);
            assert(xa == xa0 && a.signerCount() == sc0 && a.distinctRoles() == dr0);
        } else {
            // setPolicy: membership and counters untouched
            assert(xa == xa0 && xr == xr0 && a.isGuardian(x) == xg0);
            assert(a.signerCount() == sc0 && a.distinctRoles() == dr0 && a.guardianCount() == gc0);
            assert(a.roleCount(affected) == rc0);
        }
    }
}
