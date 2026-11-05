// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm} from "forge-std/Test.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";
import {TieredAuthority} from "../src/TieredAuthority.sol";

/// On-chain integration of the sanctions-ingestion tool (scripts/sanctions_ingest.py; paper Section 5.3).
/// MUST be run with `forge test --isolate --mc Ingest` so that each action is metered as a transaction.
///
/// Executes the actions in data/ingest/{v1,v2}/manifest.json (produced by scripts/tests/make_demo.py)
/// through a TieredAuthority: v1 is applied from scratch, then v2 adds and delists addresses. Checks
/// that every batch decodes and executes, carries the list's evidence hash into the compliance log,
/// costs no more than the tool's estimate and stays below the EIP-7825 cap, and that the on-chain
/// restriction set equals the list after each version.
contract Ingest is Test {
    uint256 constant TX_CAP = 1 << 24;
    TieredAuthority a;
    EnforcedToken t;
    uint256[] spk;

    function setUp() public {
        vm.warp(1_800_000_000);
        address[] memory s = new address[](5);
        uint8[] memory roles = new uint8[](5);
        bytes32[] memory att = new bytes32[](5);
        spk = new uint256[](5);
        for (uint256 i; i < 5; ++i) {
            spk[i] = 0x5000 + i;
            s[i] = vm.addr(spk[i]);
            roles[i] = i < 3 ? 0 : uint8(i - 2);
        }
        address[] memory g = new address[](2);
        (g[0], g[1]) = (address(0x6000), address(0x6001));
        a = new TieredAuthority(
            s,
            roles,
            att,
            g,
            TieredAuthority.Policy({
                mR: 2, mI: 3, rolesR: 1, rolesI: 2, gThreshold: 1, delay: 1 days, epoch: 1 days, restrictBudget: 5_000,
                valueBudget: 0
            })
        );
        t = new EnforcedToken(address(a), new address[](0));
        a.bindToken(address(t));
    }

    function _sigs(bytes32 d, uint256 n) internal view returns (bytes memory out) {
        uint256[] memory k = new uint256[](n);
        address[] memory ad = new address[](n);
        uint256[3] memory pick = [uint256(0), 1, 3]; // two roles among the first three picks
        for (uint256 i; i < n; ++i) {
            k[i] = spk[pick[i]];
            ad[i] = vm.addr(k[i]);
        }
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && ad[j] < ad[j - 1]; --j) {
                (ad[j], ad[j - 1]) = (ad[j - 1], ad[j]);
                (k[j], k[j - 1]) = (k[j - 1], k[j]);
            }
        }
        for (uint256 i; i < n; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(k[i], d);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function _txGas(Vm.Gas memory g) internal pure returns (uint256) {
        uint256 used = g.gasTotalUsed;
        uint256 refund = g.gasRefunded > 0 ? uint256(uint64(g.gasRefunded)) : 0;
        if (refund > used / 5) refund = used / 5;
        return used - refund;
    }

    /// Applies every action of one manifest; returns the largest measured transaction gas.
    function _apply(string memory path) internal returns (uint256 maxGas) {
        string memory m = vm.readFile(path);
        bytes32 e = vm.parseJsonBytes32(m, ".evidenceHash");
        for (uint256 i;; ++i) {
            string memory b = string.concat(".batches[", vm.toString(i), "]");
            if (!vm.keyExistsJson(m, b)) break;
            bytes memory data = vm.parseJsonBytes(m, string.concat(b, ".calldata"));
            assertEq(vm.parseJsonBytes32(m, string.concat(b, ".evidenceHash")), e);
            string memory tier = vm.parseJsonString(m, string.concat(b, ".tier"));
            uint256 dl = block.timestamp + 1 hours;
            uint256 n = a.nonce();
            bytes32 d = a.digest(address(t), data, e, n, dl);
            uint256 before = t.logCount();
            if (keccak256(bytes(tier)) == keccak256("fast")) {
                bytes memory sigs = _sigs(d, 2);
                a.execute(address(t), data, e, dl, sigs);
                uint256 g = _txGas(vm.lastCallGas());
                uint256 est = vm.parseJsonUint(m, string.concat(b, ".estimatedTxGas"));
                assertLe(g, est, "measured gas above the tool's estimate");
                assertLt(g, TX_CAP);
                if (g > maxGas) maxGas = g;
            } else {
                bytes memory sigs = _sigs(d, 3);
                a.queue(address(t), data, e, dl, sigs);
                vm.warp(block.timestamp + 1 days);
                a.executeQueued(address(t), data, e, n, dl);
            }
            assertEq(t.logCount(), before + 1); // one hash-chained log entry per action
        }
    }

    function _assertBlockedExactly(string memory path, address[] memory delisted) internal view {
        string memory m = vm.readFile(path);
        address[] memory list = vm.parseJsonAddressArray(m, ".addresses");
        assertEq(list.length, vm.parseJsonUint(m, ".addressCount"));
        for (uint256 i; i < list.length; ++i) assertEq(t.statusOf(list[i]), 2);
        for (uint256 i; i < delisted.length; ++i) assertEq(t.statusOf(delisted[i]), 0);
    }

    /// The tool's estimate must also hold in steady state (after other compliance actions).
    function test_estimateHoldsWarm() public {
        address[] memory w = new address[](1);
        w[0] = address(0xDEAD);
        bytes32 e = bytes32(uint256(1));
        bytes memory data = abi.encodeCall(EnforcedToken.blockBatch, (w, e));
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sg = _sigs(a.digest(address(t), data, e, a.nonce(), dl), 2);
        a.execute(address(t), data, e, dl, sg);
        uint256 cold = _txGas(vm.lastCallGas());
        uint256 g1 = _apply("data/ingest/v1/manifest.json");
        emit log_named_uint("first action on a fresh deployment (1 address), tx gas", cold);
        emit log_named_uint("largest v1 batch in steady state, tx gas", g1);
    }

    function test_applyV1ThenV2() public {
        uint256 g1 = _apply("data/ingest/v1/manifest.json");
        _assertBlockedExactly("data/ingest/v1/manifest.json", new address[](0));
        uint256 g2 = _apply("data/ingest/v2/manifest.json");
        string memory m2 = vm.readFile("data/ingest/v2/manifest.json");
        _assertBlockedExactly("data/ingest/v2/manifest.json", vm.parseJsonAddressArray(m2, ".diff.remove"));
        emit log_named_uint("largest v1 batch, tx gas", g1);
        emit log_named_uint("largest v2 batch, tx gas", g2);
    }
}
