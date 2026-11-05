// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";
import {TieredAuthority} from "../src/TieredAuthority.sol";

/// Unit tests for the asymmetric (tiered) compliance authority of Section 5.5.
///
/// Signers: s0, s1, s2 hold role 0 (compliance), s3 role 1 (legal), s4 role 2 (control).
/// Guardians: g0, g1, g2. Policy: fast tier 2-of-5 (any role), slow tier 3-of-5 covering at least
/// two roles, 2-of-3 guardians cancel, 2-day delay, 1-day budget epoch, 50 accounts and
/// 1,000,000 tokens per epoch.
contract Tiered is Test {
    bytes32 constant EV = keccak256("case-2026-017");
    uint32 constant DELAY = 2 days;
    uint32 constant EPOCH = 1 days;
    uint96 constant VALUE_BUDGET = 1_000_000e6;

    TieredAuthority a;
    EnforcedToken t;
    uint256[5] spk;
    uint256[3] gpk;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address custody = address(0xC057);

    // ------------------------------------------------------------------ setup
    function _policy() internal pure returns (TieredAuthority.Policy memory p) {
        p = TieredAuthority.Policy({
            mR: 2, mI: 3, rolesR: 1, rolesI: 2, gThreshold: 2, delay: DELAY, epoch: EPOCH, restrictBudget: 50,
            valueBudget: VALUE_BUDGET
        });
    }

    function _custodians() internal view returns (address[] memory r) {
        r = new address[](1);
        r[0] = custody;
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        address[] memory s = new address[](5);
        uint8[] memory roles = new uint8[](5);
        bytes32[] memory att = new bytes32[](5);
        for (uint256 i; i < 5; ++i) {
            spk[i] = 0x5000 + i;
            s[i] = vm.addr(spk[i]);
            roles[i] = i < 3 ? 0 : uint8(i - 2);
            att[i] = keccak256(abi.encode("hsm-attestation", i));
        }
        address[] memory g = new address[](3);
        for (uint256 i; i < 3; ++i) {
            gpk[i] = 0x6000 + i;
            g[i] = vm.addr(gpk[i]);
        }
        a = new TieredAuthority(s, roles, att, g, _policy());
        t = new EnforcedToken(address(a), _custodians());
        a.bindToken(address(t));
        t.mint(alice, 10_000_000e6);
        t.mint(bob, 1e6);
        t.mint(custody, 1);
    }

    // ------------------------------------------------------------------ helpers
    function _sign(bytes32 d, uint256[] memory pks) internal pure returns (bytes memory sigs) {
        // sort by signer address, ascending
        address[] memory ad = new address[](pks.length);
        for (uint256 i; i < pks.length; ++i) ad[i] = vm.addr(pks[i]);
        for (uint256 i = 1; i < pks.length; ++i) {
            for (uint256 j = i; j > 0 && ad[j] < ad[j - 1]; --j) {
                (ad[j], ad[j - 1]) = (ad[j - 1], ad[j]);
                (pks[j], pks[j - 1]) = (pks[j - 1], pks[j]);
            }
        }
        for (uint256 i; i < pks.length; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], d);
            sigs = bytes.concat(sigs, abi.encodePacked(r, s, v));
        }
    }

    function _s(uint256 i0, uint256 i1) internal view returns (uint256[] memory k) {
        k = new uint256[](2);
        (k[0], k[1]) = (spk[i0], spk[i1]);
    }

    function _s(uint256 i0, uint256 i1, uint256 i2) internal view returns (uint256[] memory k) {
        k = new uint256[](3);
        (k[0], k[1], k[2]) = (spk[i0], spk[i1], spk[i2]);
    }

    function _fast(bytes memory data, uint256[] memory keys) internal returns (bytes memory) {
        return _fastTo(address(t), data, keys);
    }

    function _fastTo(address target, bytes memory data, uint256[] memory keys) internal returns (bytes memory) {
        uint256 dl = block.timestamp + 1 hours;
        bytes32 d = a.digest(target, data, EV, a.nonce(), dl);
        return a.execute(target, data, EV, dl, _sign(d, keys));
    }

    /// Expect the fast tier to reject: sign first, so expectRevert applies to execute() itself.
    function _fastReverts(address target, bytes memory data, uint256[] memory keys, bytes memory err) internal {
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sigs = _sign(a.digest(target, data, EV, a.nonce(), dl), keys);
        if (err.length == 0) vm.expectRevert();
        else vm.expectRevert(err);
        a.execute(target, data, EV, dl, sigs);
    }

    function _err(bytes4 sel) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel);
    }

    function _notSigner(address x) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TieredAuthority.NotSigner.selector, x);
    }

    struct Q {
        address target;
        bytes data;
        uint256 n;
        uint256 dl;
        bytes32 id;
    }

    function _queue(address target, bytes memory data, uint256[] memory keys) internal returns (Q memory q) {
        q.target = target;
        q.data = data;
        q.n = a.nonce();
        q.dl = block.timestamp + 1 hours;
        bytes32 d = a.digest(target, data, EV, q.n, q.dl);
        q.id = a.queue(target, data, EV, q.dl, _sign(d, keys));
        assertEq(q.id, d);
    }

    function _run(Q memory q) internal returns (bytes memory) {
        return a.executeQueued(q.target, q.data, EV, q.n, q.dl);
    }

    function _slow(address target, bytes memory data) internal {
        Q memory q = _queue(target, data, _s(0, 1, 3));
        vm.warp(block.timestamp + DELAY);
        _run(q);
    }

    function _status(address x, uint8 s) internal pure returns (bytes memory) {
        return abi.encodeCall(EnforcedToken.setStatus, (x, s, EV));
    }

    function _wrapped(bytes4 sel) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TieredAuthority.CallFailed.selector, abi.encodeWithSelector(sel));
    }

    // ================================================================== fast tier: only restricts
    function test_fastFreezeBlockHold() public {
        _fast(_status(alice, 1), _s(0, 1));
        assertEq(t.statusOf(alice), 1);
        _fast(_status(alice, 2), _s(0, 3)); // Frozen -> Blocked is a further restriction
        assertEq(t.statusOf(alice), 2);
        _fast(abi.encodeCall(EnforcedToken.placeHold, (keccak256("h"), bob, 1e6, EV)), _s(3, 4));
        assertEq(t.heldOf(bob), 1e6);
        address[] memory xs = new address[](3);
        (xs[0], xs[1], xs[2]) = (address(1), address(2), address(3));
        _fast(abi.encodeCall(EnforcedToken.blockBatch, (xs, EV)), _s(1, 2));
        assertEq(t.statusOf(address(2)), 2);
    }

    function test_fastEmitsApprovers() public {
        bytes memory data = _status(alice, 1);
        uint256 dl = block.timestamp + 1;
        bytes32 d = a.digest(address(t), data, EV, a.nonce(), dl);
        address[] memory who = new address[](2);
        (who[0], who[1]) = (vm.addr(spk[0]), vm.addr(spk[3]));
        if (who[1] < who[0]) (who[0], who[1]) = (who[1], who[0]);
        vm.expectEmit(address(a));
        emit TieredAuthority.Executed(d, address(t), EV, who);
        a.execute(address(t), data, EV, dl, _sign(d, _s(0, 3)));
    }

    function test_fastRejectsEveryPermissiveOrIrreversibleAction() public {
        _fast(_status(alice, 2), _s(0, 1));
        _fast(abi.encodeCall(EnforcedToken.placeHold, (keccak256("h"), alice, 5e6, EV)), _s(0, 1));
        bytes[6] memory bad = [
            _status(alice, 1), // Blocked -> Frozen loosens
            _status(alice, 0), // unblock
            _status(alice, 2), // no-op is not a restriction
            abi.encodeCall(EnforcedToken.releaseHold, (keccak256("h"), EV)),
            abi.encodeCall(EnforcedToken.seize, (keccak256("h"), 1e6, custody, EV)),
            abi.encodeCall(EnforcedToken.burnFromHold, (keccak256("h"), 1e6, EV))
        ];
        for (uint256 i; i < bad.length; ++i) {
            uint256 dl = block.timestamp + 1;
            bytes32 d = a.digest(address(t), bad[i], EV, a.nonce(), dl);
            bytes memory sigs = _sign(d, _s(0, 1, 3)); // even a slow-tier quorum cannot use the fast tier
            vm.expectRevert(TieredAuthority.NotRestrictive.selector);
            a.execute(address(t), bad[i], EV, dl, sigs);
        }
    }

    /// Removing a seizure destination is restrictive (fast tier); adding one is not (slow tier only).
    function test_custodyAddSlowRemoveFast() public {
        address extra = address(0xC0FFEE);
        _fastReverts(
            address(t),
            abi.encodeCall(EnforcedToken.setCustody, (extra, true, EV)),
            _s(0, 1),
            _err(TieredAuthority.NotRestrictive.selector)
        );
        _slow(address(t), abi.encodeCall(EnforcedToken.setCustody, (extra, true, EV)));
        assertTrue(t.isCustody(extra));
        _fast(abi.encodeCall(EnforcedToken.setCustody, (extra, false, EV)), _s(0, 1));
        assertFalse(t.isCustody(extra));
    }

    function test_fastRejectsOtherTargetsAndConfig() public {
        _fastReverts(address(0xBEEF), _status(alice, 1), _s(0, 1), _err(TieredAuthority.NotRestrictive.selector));
        bytes memory cfg = abi.encodeCall(TieredAuthority.addSigner, (address(0x1234), 0, bytes32(0)));
        _fastReverts(address(a), cfg, _s(0, 1), _err(TieredAuthority.NotRestrictive.selector));
    }

    function test_fastNeedsQuorum() public {
        uint256[] memory one = new uint256[](1);
        one[0] = spk[0];
        _fastReverts(address(t), _status(alice, 1), one, _err(TieredAuthority.BadSignatureLength.selector));
        uint256[] memory outsider = _s(0, 1);
        outsider[1] = 0xBAD;
        _fastReverts(address(t), _status(alice, 1), outsider, _notSigner(vm.addr(0xBAD)));
        uint256[] memory guardianKey = _s(0, 1);
        guardianKey[1] = gpk[0]; // guardians are not signers
        _fastReverts(address(t), _status(alice, 1), guardianKey, _notSigner(vm.addr(gpk[0])));
        assertEq(t.statusOf(alice), 0);
    }

    function test_fastRejectsReplayAndDuplicates() public {
        bytes memory data = _status(alice, 1);
        uint256 dl = block.timestamp + 1;
        bytes32 d = a.digest(address(t), data, EV, a.nonce(), dl);
        bytes memory sigs = _sign(d, _s(0, 1));
        a.execute(address(t), data, EV, dl, sigs);
        vm.expectRevert();
        a.execute(address(t), data, EV, dl, sigs);

        bytes32 d2 = a.digest(address(t), _status(bob, 1), EV, a.nonce(), dl);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(spk[0], d2);
        bytes memory dup = bytes.concat(abi.encodePacked(r, s, v), abi.encodePacked(r, s, v));
        vm.expectRevert(TieredAuthority.SignersNotAscending.selector);
        a.execute(address(t), _status(bob, 1), EV, dl, dup);
    }

    function test_deadline() public {
        bytes memory data = _status(alice, 1);
        uint256 dl = block.timestamp - 1;
        bytes32 d = a.digest(address(t), data, EV, a.nonce(), dl);
        bytes memory sigs = _sign(d, _s(0, 1));
        vm.expectRevert(TieredAuthority.Expired.selector);
        a.execute(address(t), data, EV, dl, sigs);
    }

    // ================================================================== slow tier: quorum, roles, delay
    function test_slowNeedsHigherQuorumAndTwoRoles() public {
        bytes memory data = _status(alice, 0);
        uint256 dl = block.timestamp + 1;
        bytes32 d = a.digest(address(t), data, EV, a.nonce(), dl);
        bytes memory two = _sign(d, _s(0, 3));
        vm.expectRevert(TieredAuthority.BadSignatureLength.selector);
        a.queue(address(t), data, EV, dl, two);
        bytes memory sameRole = _sign(d, _s(0, 1, 2)); // three compliance officers, one role
        vm.expectRevert(TieredAuthority.RolesNotCovered.selector);
        a.queue(address(t), data, EV, dl, sameRole);
        a.queue(address(t), data, EV, dl, _sign(d, _s(0, 1, 3)));
    }

    function test_delayAndGrace() public {
        _fast(_status(alice, 2), _s(0, 1));
        Q memory q = _queue(address(t), _status(alice, 0), _s(0, 1, 3));
        assertEq(a.eta(q.id), block.timestamp + DELAY);
        vm.expectRevert(TieredAuthority.TooEarly.selector);
        _run(q);
        vm.warp(block.timestamp + DELAY - 1);
        vm.expectRevert(TieredAuthority.TooEarly.selector);
        _run(q);
        vm.warp(block.timestamp + 1);
        _run(q);
        assertEq(t.statusOf(alice), 0);
        vm.expectRevert(TieredAuthority.UnknownAction.selector); // executes once
        _run(q);
    }

    function test_staleActionExpires() public {
        Q memory q = _queue(address(t), _status(alice, 1), _s(0, 1, 3));
        vm.warp(block.timestamp + DELAY + a.GRACE() + 1);
        vm.expectRevert(TieredAuthority.Stale.selector);
        _run(q);
    }

    function test_slowTierCanAlsoRestrictBeyondBudget() public {
        address[] memory xs = new address[](60); // over the fast-tier budget of 50
        for (uint256 i; i < xs.length; ++i) xs[i] = address(uint160(0x9000 + i));
        _slow(address(t), abi.encodeCall(EnforcedToken.blockBatch, (xs, EV)));
        assertEq(t.statusOf(xs[59]), 2);
    }

    // ================================================================== two-phase lifecycle through the tiers
    function test_holdFastSeizeSlow() public {
        bytes32 h = keccak256("order-1");
        _fast(abi.encodeCall(EnforcedToken.placeHold, (h, alice, 300e6, EV)), _s(0, 1));
        assertEq(t.spendableOf(alice), 10_000_000e6 - 300e6);
        _slow(address(t), abi.encodeCall(EnforcedToken.seize, (h, 200e6, custody, EV)));
        _slow(address(t), abi.encodeCall(EnforcedToken.burnFromHold, (h, 100e6, EV)));
        assertEq(t.balanceOf(alice), 10_000_000e6 - 300e6);
        assertEq(t.balanceOf(custody), 200e6 + 1);
        assertEq(t.heldOf(alice), 0);
        (uint64 epochIndex,, uint96 value) = a.usage();
        assertEq(epochIndex, block.timestamp / EPOCH);
        assertEq(value, 100e6); // the seizure fell in the previous epoch; this epoch has the burn only
    }

    // ================================================================== guardian cancellation
    function test_guardiansCancel() public {
        bytes32 h = keccak256("order-2");
        _fast(abi.encodeCall(EnforcedToken.placeHold, (h, alice, 1e6, EV)), _s(0, 1));
        Q memory q = _queue(address(t), abi.encodeCall(EnforcedToken.seize, (h, 1e6, custody, EV)), _s(0, 1, 3));
        uint256[] memory g = new uint256[](2);
        (g[0], g[1]) = (gpk[0], gpk[2]);
        a.cancel(q.id, _sign(a.cancelDigest(q.id), g));
        assertEq(a.eta(q.id), 0);
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(TieredAuthority.UnknownAction.selector);
        _run(q);
        assertEq(t.heldOf(alice), 1e6); // the hold is untouched
    }

    function test_cancelNeedsGuardianQuorum() public {
        Q memory q = _queue(address(t), _status(alice, 1), _s(0, 1, 3));
        bytes32 cd = a.cancelDigest(q.id);
        uint256[] memory one = new uint256[](1);
        one[0] = gpk[0];
        vm.expectRevert(TieredAuthority.BadSignatureLength.selector);
        a.cancel(q.id, _sign(cd, one));
        uint256[] memory withSigner = new uint256[](2);
        (withSigner[0], withSigner[1]) = (gpk[0], spk[0]); // a signer is not a guardian
        vm.expectRevert();
        a.cancel(q.id, _sign(cd, withSigner));
        vm.expectRevert(TieredAuthority.UnknownAction.selector);
        a.cancel(keccak256("nothing queued"), _sign(cd, one));
    }

    // ================================================================== budgets
    function test_restrictBudgetPerEpoch() public {
        address[] memory xs = new address[](50);
        for (uint256 i; i < xs.length; ++i) xs[i] = address(uint160(0x7000 + i));
        _fast(abi.encodeCall(EnforcedToken.blockBatch, (xs, EV)), _s(0, 1));
        _fastReverts(address(t), _status(alice, 1), _s(0, 1), _err(TieredAuthority.BudgetExceeded.selector));
        vm.warp(block.timestamp + EPOCH);
        _fast(_status(alice, 1), _s(0, 1)); // a new epoch resets the budget
        assertEq(t.statusOf(alice), 1);
    }

    function test_valueBudgetAndRaisingIt() public {
        bytes32 h = keccak256("order-3");
        _fast(abi.encodeCall(EnforcedToken.placeHold, (h, alice, 3_000_000e6, EV)), _s(0, 1));
        Q memory big = _queue(address(t), abi.encodeCall(EnforcedToken.seize, (h, 3_000_000e6, custody, EV)), _s(0, 1, 3));
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(TieredAuthority.BudgetExceeded.selector);
        _run(big);

        // raising the budget is itself a delayed, cancellable slow-tier action
        TieredAuthority.Policy memory p = _policy();
        p.valueBudget = 5_000_000e6;
        _slow(address(a), abi.encodeCall(TieredAuthority.setPolicy, (p)));
        _run(big); // still inside its grace period
        assertEq(t.balanceOf(custody), 3_000_000e6 + 1);
    }

    /// The value budget is not limited to the bound token: a second token that names this authority,
    /// and a token before bindToken(), are counted against the same per-epoch budget.
    function test_valueBudgetCoversEveryTarget() public {
        // a second token controlled by the same authority
        EnforcedToken t2 = new EnforcedToken(address(a), _custodians());
        t2.mint(alice, 10_000_000e6);
        bytes32 h = keccak256("order-other-token");
        _slow(address(t2), abi.encodeCall(EnforcedToken.placeHold, (h, alice, 3_000_000e6, EV)));
        Q memory q = _queue(address(t2), abi.encodeCall(EnforcedToken.seize, (h, 3_000_000e6, custody, EV)), _s(0, 1, 3));
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(TieredAuthority.BudgetExceeded.selector);
        _run(q);

        // a fresh authority whose token is not bound yet
        address[] memory s = new address[](5);
        uint8[] memory roles = new uint8[](5);
        bytes32[] memory att = new bytes32[](5);
        for (uint256 i; i < 5; ++i) {
            s[i] = vm.addr(spk[i]);
            roles[i] = i < 3 ? 0 : uint8(i - 2);
        }
        address[] memory g = new address[](3);
        for (uint256 i; i < 3; ++i) g[i] = vm.addr(gpk[i]);
        TieredAuthority b = new TieredAuthority(s, roles, att, g, _policy());
        EnforcedToken t3 = new EnforcedToken(address(b), _custodians());
        t3.mint(alice, 10_000_000e6);
        assertEq(b.token(), address(0));
        (TieredAuthority prev, EnforcedToken prevT) = (a, t);
        a = b;
        _slow(address(t3), abi.encodeCall(EnforcedToken.placeHold, (h, alice, 3_000_000e6, EV)));
        q = _queue(address(t3), abi.encodeCall(EnforcedToken.seize, (h, 3_000_000e6, custody, EV)), _s(0, 1, 3));
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(TieredAuthority.BudgetExceeded.selector);
        _run(q);
        (a, t) = (prev, prevT);
    }

    // ================================================================== configuration
    function test_configOnlyThroughSlowTier() public {
        vm.expectRevert(TieredAuthority.OnlySelf.selector);
        a.addSigner(address(0x1234), 0, bytes32(0));
        vm.expectRevert(TieredAuthority.OnlySelf.selector);
        a.removeSigner(vm.addr(spk[0]));
        vm.expectRevert(TieredAuthority.OnlySelf.selector);
        a.addGuardian(address(0x1234));
        vm.expectRevert(TieredAuthority.OnlySelf.selector);
        a.removeGuardian(vm.addr(gpk[0]));
        vm.expectRevert(TieredAuthority.OnlySelf.selector);
        a.setPolicy(_policy());
    }

    function test_signerRotationWithAttestation() public {
        uint256 newPk = 0x5555;
        address n = vm.addr(newPk);
        bytes32 att = keccak256("new-hsm-attestation");
        Q memory add = _queue(address(a), abi.encodeCall(TieredAuthority.addSigner, (n, 0, att)), _s(0, 1, 3));
        vm.warp(block.timestamp + DELAY);
        vm.expectEmit(address(a));
        emit TieredAuthority.SignerAdded(n, 0, att);
        _run(add);
        _slow(address(a), abi.encodeCall(TieredAuthority.removeSigner, (vm.addr(spk[0]))));
        (bool active, uint8 role, bytes32 recorded) = a.signers(n);
        assertTrue(active);
        assertEq(role, 0);
        assertEq(recorded, att);
        assertEq(a.signerCount(), 5);

        _fastReverts(address(t), _status(alice, 1), _s(0, 1), _notSigner(vm.addr(spk[0]))); // rotated-out key rejected
        uint256[] memory k = _s(1, 1);
        k[1] = newPk;
        _fast(_status(alice, 1), k);
        assertEq(t.statusOf(alice), 1);
    }

    function test_policyCannotBeWeakened() public {
        TieredAuthority.Policy[5] memory bad;
        for (uint256 i; i < 5; ++i) bad[i] = _policy();
        bad[0].mI = 2; // slow tier no stronger than fast tier
        bad[1].delay = 1 minutes; // below MIN_DELAY
        bad[2].gThreshold = 0; // no cancel quorum
        bad[3].gThreshold = 4; // more guardians than exist
        bad[4].rolesI = 4; // more roles than signers cover
        for (uint256 i; i < 5; ++i) {
            Q memory q = _queue(address(a), abi.encodeCall(TieredAuthority.setPolicy, (bad[i])), _s(0, 1, 3));
            vm.warp(block.timestamp + DELAY);
            vm.expectRevert(_wrapped(TieredAuthority.BadPolicy.selector));
            _run(q);
        }
    }

    function test_removalCannotBreakQuorumOrRoles() public {
        // Removing the only legal signer leaves compliance + control: still two roles, allowed.
        // Removing the only control signer as well would leave one role (< rolesI): rejected.
        _slow(address(a), abi.encodeCall(TieredAuthority.removeSigner, (vm.addr(spk[3]))));
        Q memory q = _queue(address(a), abi.encodeCall(TieredAuthority.removeSigner, (vm.addr(spk[4]))), _s(0, 1, 4));
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(_wrapped(TieredAuthority.BadPolicy.selector));
        _run(q);

        // and the signer count can never drop below mI
        _slow2(abi.encodeCall(TieredAuthority.removeSigner, (vm.addr(spk[2]))));
        Q memory q2 =
            _queue(address(a), abi.encodeCall(TieredAuthority.removeSigner, (vm.addr(spk[1]))), _s(0, 1, 4));
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(_wrapped(TieredAuthority.BadPolicy.selector));
        _run(q2);
    }

    function _slow2(bytes memory data) internal {
        Q memory q = _queue(address(a), data, _s(0, 1, 4));
        vm.warp(block.timestamp + DELAY);
        _run(q);
    }

    function test_guardiansAndSignersStayDisjoint() public {
        Q memory q1 =
            _queue(address(a), abi.encodeCall(TieredAuthority.addSigner, (vm.addr(gpk[0]), 1, bytes32(0))), _s(0, 1, 3));
        Q memory q2 = _queue(address(a), abi.encodeCall(TieredAuthority.addGuardian, (vm.addr(spk[0]))), _s(0, 1, 3));
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert();
        _run(q1);
        vm.expectRevert();
        _run(q2);
    }

    // ================================================================== binding and chain separation
    function test_bindTokenOnceByDeployer() public {
        vm.expectRevert(TieredAuthority.AlreadyBound.selector);
        a.bindToken(address(0x1));
        vm.prank(alice);
        vm.expectRevert(TieredAuthority.NotDeployer.selector);
        a.bindToken(address(0x1));
    }

    function test_bindRequiresTokenControlledByThisAuthority() public {
        address[] memory s = new address[](3);
        uint8[] memory roles = new uint8[](3);
        bytes32[] memory att = new bytes32[](3);
        for (uint256 i; i < 3; ++i) {
            s[i] = vm.addr(spk[i + 2]);
            roles[i] = uint8(i);
        }
        address[] memory g = new address[](2);
        (g[0], g[1]) = (vm.addr(gpk[0]), vm.addr(gpk[1]));
        TieredAuthority.Policy memory p = _policy();
        p.rolesI = 2;
        TieredAuthority b = new TieredAuthority(s, roles, att, g, p);
        vm.expectRevert(TieredAuthority.WrongToken.selector);
        b.bindToken(address(t)); // t is controlled by `a`, not by `b`
        EnforcedToken own = new EnforcedToken(address(b), _custodians());
        b.bindToken(address(own));
        assertEq(b.token(), address(own));
    }

    function test_signatureNotValidAfterChainIdChange() public {
        bytes memory data = _status(alice, 1);
        uint256 dl = block.timestamp + 1;
        bytes32 d = a.digest(address(t), data, EV, a.nonce(), dl);
        bytes memory sigs = _sign(d, _s(0, 1));
        vm.chainId(block.chainid + 1); // e.g. the other side of a fork
        assertTrue(a.digest(address(t), data, EV, a.nonce(), dl) != d);
        vm.expectRevert();
        a.execute(address(t), data, EV, dl, sigs);
    }
}
