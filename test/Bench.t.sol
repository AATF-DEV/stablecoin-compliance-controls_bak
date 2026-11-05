// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {BaselineToken} from "../src/BaselineToken.sol";
import {BlacklistToken} from "../src/BlacklistToken.sol";
import {NaiveHoldsToken} from "../src/NaiveHoldsToken.sol";
import {AggregateHoldsToken} from "../src/AggregateHoldsToken.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";
import {SMTToken} from "../src/SMTToken.sol";
import {ComplianceAuthority} from "../src/ComplianceAuthority.sol";
import {TieredAuthority} from "../src/TieredAuthority.sol";
import {BridgedEnforcedToken} from "../src/BridgedEnforcedToken.sol";
import {XChainAdapter, IXERC20} from "../src/XChainAdapter.sol";

/// Gas benchmarks. MUST be run with `forge test --isolate --mc Bench` so that every
/// top-level call is metered as its own transaction (cold storage, fresh refunds).
///
/// Reported transaction cost (Prague/Osaka rules):
///   standard = 21000 + 4*zeroBytes + 16*nonZeroBytes + execGas
///   floor    = 21000 + 10*(zeroBytes + 4*nonZeroBytes)          (EIP-7623)
///   total    = max(standard - min(refund, standard/5), floor)    (EIP-3529)
contract Bench is Test {
    uint256 constant TX_CAP = 1 << 24; // EIP-7825
    bytes32 constant EV = keccak256("case-file:2026-001");

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    // ------------------------------------------------------------- helpers
    /// Under `--isolate`, forge 1.5.x reports in `gasTotalUsed` the whole transaction's gas
    /// before refunds: 21000 + calldata cost (+ EIP-7623 floor if binding) + execution.
    /// (Verified empirically: appending 1000 non-zero calldata bytes raises it to exactly
    /// 21000 + 10 * tokens, i.e. the floor.) We subtract the capped refund and re-apply the floor.
    function _cost(bytes memory cd, Vm.Gas memory g)
        internal
        pure
        returns (uint256 total, uint256 intrinsic, uint256 exec, uint256 refund)
    {
        uint256 z;
        uint256 nz;
        for (uint256 i; i < cd.length; ++i) {
            if (cd[i] == 0) z++;
            else nz++;
        }
        intrinsic = 21000 + 4 * z + 16 * nz;
        uint256 floor_ = 21000 + 10 * (z + 4 * nz);
        uint256 used = g.gasTotalUsed;
        exec = used > intrinsic ? used - intrinsic : 0;
        refund = g.gasRefunded > 0 ? uint256(uint64(g.gasRefunded)) : 0;
        if (refund > used / 5) refund = used / 5;
        total = used - refund;
        if (total < floor_) total = floor_;
    }

    function _row(string memory file, string memory variant, uint256 param, bytes memory cd, Vm.Gas memory g)
        internal
        returns (uint256 total)
    {
        (uint256 t, uint256 intrinsic, uint256 exec, uint256 refund) = _cost(cd, g);
        total = t;
        vm.writeLine(
            file,
            string.concat(
                variant, ",", vm.toString(param), ",", vm.toString(exec), ",", vm.toString(refund), ",",
                vm.toString(cd.length), ",", vm.toString(intrinsic), ",", vm.toString(total), ",",
                total > TX_CAP ? "1" : "0"
            )
        );
    }

    function _header(string memory file) internal {
        vm.writeFile(file, "variant,param,exec_gas,refund,calldata_bytes,intrinsic_gas,tx_gas,exceeds_eip7825\n");
    }

    // quorum helpers ------------------------------------------------------
    function _one(address x) internal pure returns (address[] memory r) {
        r = new address[](1);
        r[0] = x;
    }

    function _signers(uint256 n) internal pure returns (uint256[] memory pks, address[] memory addrs) {
        pks = new uint256[](n);
        addrs = new address[](n);
        for (uint256 i; i < n; ++i) {
            pks[i] = 0x1000 + i;
            addrs[i] = vm.addr(pks[i]);
        }
        // sort ascending by address (insertion sort, tiny n)
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && addrs[j] < addrs[j - 1]; --j) {
                (addrs[j], addrs[j - 1]) = (addrs[j - 1], addrs[j]);
                (pks[j], pks[j - 1]) = (pks[j - 1], pks[j]);
            }
        }
    }

    function _authority(uint256 m, uint256 n) internal returns (ComplianceAuthority a, uint256[] memory pks) {
        address[] memory addrs;
        (pks, addrs) = _signers(n);
        a = new ComplianceAuthority(addrs, m);
    }

    /// signs with the first m keys (already ascending) and returns execute() calldata
    function _execCalldata(ComplianceAuthority a, uint256[] memory pks, uint256 m, address target, bytes memory data)
        internal
        view
        returns (bytes memory)
    {
        uint256 deadline = block.timestamp + 1 days;
        bytes32 d = a.digest(target, data, EV, a.nonce(), deadline);
        bytes memory sigs;
        for (uint256 i; i < m; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], d);
            sigs = bytes.concat(sigs, abi.encodePacked(r, s, v));
        }
        return abi.encodeCall(ComplianceAuthority.execute, (target, data, EV, deadline, sigs));
    }

    function _exec(ComplianceAuthority a, bytes memory cd) internal {
        (bool ok, bytes memory ret) = address(a).call(cd);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// One prior action so the measured call sees steady-state storage (quorum nonce,
    /// log head and log counter already non-zero), as on a live deployment.
    function _warm(ComplianceAuthority a, uint256[] memory pks, uint256 m, address target, bytes memory data)
        internal
    {
        _exec(a, _execCalldata(a, pks, m, target, data));
    }

    function WARM_ENF() internal pure returns (bytes memory) {
        return abi.encodeCall(EnforcedToken.setStatus, (address(0xDEAD), 2, EV));
    }

    // ===================================================================
    // A. per-transfer cost vs. number of active holds on the sender
    // ===================================================================
    function test_A_transferVsHolds() public {
        string memory f = "results/transfer_holds.csv";
        _header(f);
        bytes memory cd = abi.encodeWithSignature("transfer(address,uint256)", bob, 1000e6);

        {
            BaselineToken t = new BaselineToken();
            t.mint(alice, 1_000_000e6);
            t.mint(bob, 1e6);
            vm.prank(alice);
            t.transfer(bob, 1000e6);
            _row(f, "baseline", 0, cd, vm.lastCallGas());
        }
        {
            BlacklistToken t = new BlacklistToken(address(this));
            t.mint(alice, 1_000_000e6);
            t.mint(bob, 1e6);
            vm.prank(alice);
            t.transfer(bob, 1000e6);
            _row(f, "blacklist_mapping", 0, cd, vm.lastCallGas());
        }

        uint256[6] memory ks = [uint256(0), 1, 2, 4, 8, 16];
        for (uint256 x; x < ks.length; ++x) {
            uint256 k = ks[x];
            NaiveHoldsToken t = new NaiveHoldsToken(address(this));
            t.mint(alice, 1_000_000e6);
            t.mint(bob, 1e6);
            for (uint256 i; i < k; ++i) t.placeHold(alice, 1e6);
            vm.prank(alice);
            t.transfer(bob, 1000e6);
            _row(f, "naive_holds", k, cd, vm.lastCallGas());
        }
        for (uint256 x; x < ks.length; ++x) {
            uint256 k = ks[x];
            AggregateHoldsToken t = new AggregateHoldsToken(address(this));
            t.mint(alice, 1_000_000e6);
            t.mint(bob, 1e6);
            for (uint256 i; i < k; ++i) t.placeHold(alice, 1e6);
            vm.prank(alice);
            t.transfer(bob, 1000e6);
            _row(f, "separate_aggregate", k, cd, vm.lastCallGas());
        }
        for (uint256 x; x < ks.length; ++x) {
            uint256 k = ks[x];
            EnforcedToken t = new EnforcedToken(address(this), new address[](0));
            t.mint(alice, 1_000_000e6);
            t.mint(bob, 1e6);
            for (uint256 i; i < k; ++i) t.placeHold(keccak256(abi.encode(k, i)), alice, 1e6, EV);
            vm.prank(alice);
            t.transfer(bob, 1000e6);
            _row(f, "enforced_packed", k, cd, vm.lastCallGas());
        }
    }

    // ===================================================================
    // B. SMT transfer cost vs. size of the restricted set
    // ===================================================================
    function _proof(string memory json, string memory who) internal pure returns (SMTToken.Proof memory p) {
        p.bitmap = vm.parseUint(vm.parseJsonString(json, string.concat(".", who, ".bitmap")));
        p.siblings = vm.parseJsonBytes32Array(json, string.concat(".", who, ".siblings"));
    }

    function test_B_smtTransferVsSetSize() public {
        string memory f = "results/smt_transfer.csv";
        _header(f);
        uint256[6] memory ns = [uint256(1), 10, 100, 1000, 10000, 100000];
        address sender = 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4;
        address recipient = 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2;
        for (uint256 x; x < ns.length; ++x) {
            string memory json = vm.readFile(string.concat("data/smt_", vm.toString(ns[x]), ".json"));
            SMTToken t = new SMTToken(address(this));
            t.setRoot(vm.parseJsonBytes32(json, ".root"));
            t.mint(sender, 1_000_000e6);
            t.mint(recipient, 1e6);
            SMTToken.Proof memory pf = _proof(json, "sender");
            SMTToken.Proof memory pt = _proof(json, "recipient");
            vm.prank(sender);
            t.transferWithProofs(recipient, 1000e6, pf, pt);
            Vm.Gas memory g = vm.lastCallGas();
            bytes memory cd = abi.encodeCall(SMTToken.transferWithProofs, (recipient, 1000e6, pf, pt));
            _row(f, "smt_proofs", ns[x], cd, g);
        }
    }

    // ===================================================================
    // C. quorum authorization overhead vs. M (N = M + 2)
    // ===================================================================
    function test_C_quorumOverhead() public {
        string memory f = "results/quorum.csv";
        _header(f);
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (bob, 1, EV));
        {
            address key = address(0xC0FFEE);
            EnforcedToken t = new EnforcedToken(key, new address[](0));
            vm.prank(key);
            t.setStatus(address(0xDEAD), 2, EV); // warm-up
            vm.prank(key);
            t.setStatus(bob, 1, EV);
            _row(f, "single_key", 1, data, vm.lastCallGas());
        }
        for (uint256 m = 1; m <= 5; ++m) {
            (ComplianceAuthority a, uint256[] memory pks) = _authority(m, m + 2);
            EnforcedToken t = new EnforcedToken(address(a), new address[](0));
            _warm(a, pks, m, address(t), WARM_ENF());
            bytes memory cd = _execCalldata(a, pks, m, address(t), data);
            _exec(a, cd);
            _row(f, "quorum", m, cd, vm.lastCallGas());
            assertEq(t.statusOf(bob), 1);
        }
    }

    // ===================================================================
    // D. restriction-list update cost vs. batch size K (2-of-3 quorum)
    // ===================================================================
    function _addrs(uint256 k, uint256 salt) internal pure returns (address[] memory xs) {
        xs = new address[](k);
        for (uint256 i; i < k; ++i) {
            xs[i] = address(uint160(uint256(keccak256(abi.encode(salt, i)))));
        }
    }

    function test_D_batchUpdate() public {
        string memory f = "results/batch_update.csv";
        _header(f);
        uint256[9] memory ks = [uint256(1), 10, 50, 100, 250, 500, 600, 750, 1000];
        for (uint256 x; x < ks.length; ++x) {
            uint256 k = ks[x];
            address[] memory xs = _addrs(k, k);

            // (1) separate blacklist mapping, unfunded targets: zero -> non-zero SSTORE
            {
                (ComplianceAuthority a, uint256[] memory pks) = _authority(2, 3);
                BlacklistToken t = new BlacklistToken(address(a));
                address[] memory w = new address[](1);
                w[0] = address(0xDEAD);
                _warm(a, pks, 2, address(t), abi.encodeCall(BlacklistToken.blacklistBatch, (w)));
                bytes memory cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(BlacklistToken.blacklistBatch, (xs)));
                _exec(a, cd);
                _row(f, "mapping", k, cd, vm.lastCallGas());
            }
            // (2) packed status, targets already hold a balance: non-zero -> non-zero SSTORE
            {
                (ComplianceAuthority a, uint256[] memory pks) = _authority(2, 3);
                EnforcedToken t = new EnforcedToken(address(a), new address[](0));
                for (uint256 i; i < k; ++i) t.mint(xs[i], 1e6);
                _warm(a, pks, 2, address(t), WARM_ENF());
                bytes memory cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.blockBatch, (xs, EV)));
                _exec(a, cd);
                _row(f, "packed_funded", k, cd, vm.lastCallGas());
                assertEq(t.statusOf(xs[k - 1]), 2);
            }
            // (2b) packed status, targets with no balance: zero -> non-zero SSTORE
            {
                (ComplianceAuthority a, uint256[] memory pks) = _authority(2, 3);
                EnforcedToken t = new EnforcedToken(address(a), new address[](0));
                _warm(a, pks, 2, address(t), WARM_ENF());
                bytes memory cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.blockBatch, (xs, EV)));
                _exec(a, cd);
                _row(f, "packed_unfunded", k, cd, vm.lastCallGas());
            }
            // (3) SMT: only the 32-byte root changes, independent of K
            {
                (ComplianceAuthority a, uint256[] memory pks) = _authority(2, 3);
                SMTToken t = new SMTToken(address(a));
                _warm(a, pks, 2, address(t), abi.encodeCall(SMTToken.setRoot, (keccak256("genesis"))));
                bytes32 r = keccak256(abi.encode("root", k));
                bytes memory cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(SMTToken.setRoot, (r)));
                _exec(a, cd);
                _row(f, "smt_root", k, cd, vm.lastCallGas());
            }
        }
    }

    // ===================================================================
    // E. two-phase enforcement lifecycle, each action via 2-of-3 quorum
    // ===================================================================
    function test_E_lifecycle() public {
        string memory f = "results/lifecycle.csv";
        _header(f);
        (ComplianceAuthority a, uint256[] memory pks) = _authority(2, 3);
        address treasury = address(0x7EA5);
        EnforcedToken t = new EnforcedToken(address(a), _one(treasury));
        t.mint(alice, 1_000_000e6);
        t.mint(treasury, 1e6);
        _warm(a, pks, 2, address(t), WARM_ENF());
        bytes32 h1 = keccak256("hold-1");
        bytes32 h2 = keccak256("hold-2");
        bytes memory cd;

        cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV)));
        _exec(a, cd);
        _row(f, "freeze", 0, cd, vm.lastCallGas());

        cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.placeHold, (h1, alice, 100e6, EV)));
        _exec(a, cd);
        _row(f, "place_hold", 0, cd, vm.lastCallGas());

        cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.placeHold, (h2, alice, 50e6, EV)));
        _exec(a, cd);

        cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.seize, (h1, 100e6, treasury, EV)));
        _exec(a, cd);
        _row(f, "seize_full", 0, cd, vm.lastCallGas());

        cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.burnFromHold, (h2, 20e6, EV)));
        _exec(a, cd);
        _row(f, "burn_partial", 0, cd, vm.lastCallGas());

        cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.releaseHold, (h2, EV)));
        _exec(a, cd);
        _row(f, "release", 0, cd, vm.lastCallGas());

        cd = _execCalldata(a, pks, 2, address(t), abi.encodeCall(EnforcedToken.setStatus, (alice, 0, EV)));
        _exec(a, cd);
        _row(f, "unfreeze", 0, cd, vm.lastCallGas());

        assertEq(t.balanceOf(alice), 1_000_000e6 - 120e6);
        assertEq(t.balanceOf(treasury), 101e6);
        assertEq(t.totalSupply(), 1_000_001e6 - 20e6);
        assertEq(t.logCount(), 8);
    }

    // ===================================================================
    // F. tiered authority (Section 5.5): fast tier 2-of-5, slow tier 3-of-5 covering
    //    two roles, guardian cancel 2-of-3. Steady state: one prior fast action in the
    //    same epoch, so the nonce, budget usage and log head are already non-zero.
    // ===================================================================
    function _tiered() internal returns (TieredAuthority a, uint256[] memory spk, uint256[] memory gpk) {
        spk = new uint256[](5);
        address[] memory s = new address[](5);
        uint8[] memory roles = new uint8[](5);
        bytes32[] memory att = new bytes32[](5);
        for (uint256 i; i < 5; ++i) {
            spk[i] = 0x5000 + i;
            s[i] = vm.addr(spk[i]);
            roles[i] = i < 3 ? 0 : uint8(i - 2);
            att[i] = keccak256(abi.encode("hsm", i));
        }
        gpk = new uint256[](3);
        address[] memory g = new address[](3);
        for (uint256 i; i < 3; ++i) {
            gpk[i] = 0x6000 + i;
            g[i] = vm.addr(gpk[i]);
        }
        a = new TieredAuthority(
            s,
            roles,
            att,
            g,
            TieredAuthority.Policy({
                mR: 2, mI: 3, rolesR: 1, rolesI: 2, gThreshold: 2, delay: 2 days, epoch: 1 days, restrictBudget: 1000,
                valueBudget: type(uint96).max
            })
        );
    }

    /// signatures by the given keys, ordered by ascending signer address
    function _sortedSigs(bytes32 d, uint256[] memory keys) internal pure returns (bytes memory sigs) {
        address[] memory ad = new address[](keys.length);
        for (uint256 i; i < keys.length; ++i) ad[i] = vm.addr(keys[i]);
        for (uint256 i = 1; i < keys.length; ++i) {
            for (uint256 j = i; j > 0 && ad[j] < ad[j - 1]; --j) {
                (ad[j], ad[j - 1]) = (ad[j - 1], ad[j]);
                (keys[j], keys[j - 1]) = (keys[j - 1], keys[j]);
            }
        }
        for (uint256 i; i < keys.length; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], d);
            sigs = bytes.concat(sigs, abi.encodePacked(r, s, v));
        }
    }

    function _pick(uint256[] memory k, uint256 i0, uint256 i1) internal pure returns (uint256[] memory o) {
        o = new uint256[](2);
        (o[0], o[1]) = (k[i0], k[i1]);
    }

    function _pick(uint256[] memory k, uint256 i0, uint256 i1, uint256 i2) internal pure returns (uint256[] memory o) {
        o = new uint256[](3);
        (o[0], o[1], o[2]) = (k[i0], k[i1], k[i2]);
    }

    function _fastCd(TieredAuthority a, address tgt, bytes memory data, uint256[] memory keys)
        internal
        view
        returns (bytes memory)
    {
        uint256 dl = block.timestamp + 1 hours;
        bytes32 d = a.digest(tgt, data, EV, a.nonce(), dl);
        return abi.encodeCall(TieredAuthority.execute, (tgt, data, EV, dl, _sortedSigs(d, keys)));
    }

    function _queueCd(TieredAuthority a, address tgt, bytes memory data, uint256[] memory keys)
        internal
        view
        returns (bytes memory cd, uint256 n, uint256 dl)
    {
        n = a.nonce();
        dl = block.timestamp + 1 hours;
        bytes32 d = a.digest(tgt, data, EV, n, dl);
        cd = abi.encodeCall(TieredAuthority.queue, (tgt, data, EV, dl, _sortedSigs(d, keys)));
    }

    function _call(address target, bytes memory cd) internal {
        (bool ok, bytes memory ret) = target.call(cd);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    function test_F_tiered() public {
        string memory f = "results/tiered.csv";
        _header(f);
        vm.warp(1_800_000_000);
        (TieredAuthority a, uint256[] memory spk, uint256[] memory gpk) = _tiered();
        address treasury = address(0x7EA5);
        EnforcedToken t = new EnforcedToken(address(a), _one(treasury));
        a.bindToken(address(t));
        t.mint(alice, 1_000_000e6);
        t.mint(treasury, 1e6);
        _call(address(a), _fastCd(a, address(t), WARM_ENF(), _pick(spk, 0, 1))); // warm-up
        bytes memory cd;

        // fast tier
        cd = _fastCd(a, address(t), abi.encodeCall(EnforcedToken.setStatus, (bob, 1, EV)), _pick(spk, 0, 3));
        _call(address(a), cd);
        _row(f, "fast_freeze_zero_balance", 2, cd, vm.lastCallGas());

        cd = _fastCd(a, address(t), abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV)), _pick(spk, 0, 3));
        _call(address(a), cd);
        _row(f, "fast_freeze_funded", 2, cd, vm.lastCallGas());

        bytes32 h = keccak256("hold-1");
        cd = _fastCd(a, address(t), abi.encodeCall(EnforcedToken.placeHold, (h, alice, 100e6, EV)), _pick(spk, 0, 3));
        _call(address(a), cd);
        _row(f, "fast_place_hold", 2, cd, vm.lastCallGas());

        // slow tier: queue, then execute after the delay
        bytes memory seizeData = abi.encodeCall(EnforcedToken.seize, (h, 100e6, treasury, EV));
        (bytes memory qcd, uint256 n, uint256 dl) = _queueCd(a, address(t), seizeData, _pick(spk, 0, 1, 3));
        _call(address(a), qcd);
        _row(f, "slow_queue_seize", 3, qcd, vm.lastCallGas());
        vm.warp(block.timestamp + 2 days);
        cd = abi.encodeCall(TieredAuthority.executeQueued, (address(t), seizeData, EV, n, dl));
        _call(address(a), cd);
        _row(f, "slow_execute_seize", 3, cd, vm.lastCallGas());

        bytes memory unfreeze = abi.encodeCall(EnforcedToken.setStatus, (alice, 0, EV));
        (qcd, n, dl) = _queueCd(a, address(t), unfreeze, _pick(spk, 0, 1, 3));
        _call(address(a), qcd);
        _row(f, "slow_queue_unfreeze", 3, qcd, vm.lastCallGas());
        vm.warp(block.timestamp + 2 days);
        cd = abi.encodeCall(TieredAuthority.executeQueued, (address(t), unfreeze, EV, n, dl));
        _call(address(a), cd);
        _row(f, "slow_execute_unfreeze", 3, cd, vm.lastCallGas());

        // guardian cancellation of a queued action
        (qcd, n, dl) = _queueCd(a, address(t), abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV)), _pick(spk, 0, 1, 3));
        _call(address(a), qcd);
        bytes32 id = a.digest(address(t), abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV)), EV, n, dl);
        cd = abi.encodeCall(TieredAuthority.cancel, (id, _sortedSigs(a.cancelDigest(id), _pick(gpk, 0, 2))));
        _call(address(a), cd);
        _row(f, "guardian_cancel", 2, cd, vm.lastCallGas());

        assertEq(t.balanceOf(treasury), 101e6);
        assertEq(t.statusOf(alice), 0);
        assertEq(a.eta(id), 0);
    }

    // ===================================================================
    // G. bridged token (ERC-7281): bridge-out / bridge-in through an allow-listed adapter,
    //    a plain transfer on the bridged token, and a fast-tier bridge shutdown (2-of-5).
    //    Limits were raised through the slow tier; the measured calls run in steady state.
    // ===================================================================
    function test_G_bridge() public {
        string memory f = "results/bridge.csv";
        _header(f);
        vm.warp(1_800_000_000);
        (TieredAuthority a, uint256[] memory spk,) = _tiered();
        BridgedEnforcedToken t = new BridgedEnforcedToken(address(a), new address[](0));
        a.bindToken(address(t));
        XChainAdapter br = new XChainAdapter(IXERC20(address(t)), address(this));
        t.mint(alice, 1_000_000e6);
        t.mint(bob, 1e6);
        vm.prank(alice);
        t.approve(address(br), type(uint256).max);

        bytes memory lim = abi.encodeCall(BridgedEnforcedToken.setLimits, (address(br), 1_000_000e6, 1_000_000e6, EV));
        (bytes memory qcd, uint256 n, uint256 dl) = _queueCd(a, address(t), lim, _pick(spk, 0, 1, 3));
        _call(address(a), qcd);
        vm.warp(block.timestamp + 2 days);
        _call(address(a), abi.encodeCall(TieredAuthority.executeQueued, (address(t), lim, EV, n, dl)));
        _call(address(a), _fastCd(a, address(t), WARM_ENF(), _pick(spk, 0, 1))); // warm-up
        vm.prank(alice);
        br.send(alice, 1e6, 10); // warm-up: limit timestamp and adapter counter non-zero
        br.deliver(bob, 1e6);

        bytes memory cd = abi.encodeCall(XChainAdapter.send, (alice, 1000e6, 10));
        vm.prank(alice);
        br.send(alice, 1000e6, 10);
        _row(f, "bridge_out_burn", 0, cd, vm.lastCallGas());

        cd = abi.encodeCall(XChainAdapter.deliver, (bob, 1000e6));
        br.deliver(bob, 1000e6);
        _row(f, "bridge_in_mint", 0, cd, vm.lastCallGas());

        cd = abi.encodeWithSignature("transfer(address,uint256)", bob, 1000e6);
        vm.prank(alice);
        t.transfer(bob, 1000e6);
        _row(f, "bridged_token_transfer", 0, cd, vm.lastCallGas());

        cd = _fastCd(a, address(t), abi.encodeCall(BridgedEnforcedToken.setLimits, (address(br), 0, 0, EV)), _pick(spk, 0, 3));
        _call(address(a), cd);
        _row(f, "fast_bridge_shutdown", 2, cd, vm.lastCallGas());
        assertEq(t.mintingMaxLimitOf(address(br)), 0);
    }
}
