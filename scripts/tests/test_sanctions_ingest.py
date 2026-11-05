"""Unit tests for scripts/sanctions_ingest.py (run: python3 -m unittest discover -s scripts/tests)."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import sanctions_ingest as si  # noqa: E402
import sdn_fixtures as fx  # noqa: E402


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = si.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def pair(self, name: str, evm: list[str], date="10/01/2026", **kw) -> list[str]:
        a, b = fx.write_pair(self.tmp / name, fx.list_entries(evm, name, **kw), date)
        return ["--source", str(a), "--source", str(b)]

    def build(self, src: list[str], out="out", *extra: str) -> tuple[int, str, str, dict | None]:
        code, o, e = run("build", *src, "--out", str(self.tmp / out), *extra)
        m = self.tmp / out / "manifest.json"
        return code, o, e, json.loads(m.read_text()) if code in (0, 3) and m.exists() else None


# ============================================================================ primitives
class Primitives(unittest.TestCase):
    def test_eip55_vectors(self):
        for v in ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
                  "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"):
            self.assertEqual(si.to_checksum(v.lower()), v)
            self.assertEqual(si.classify(v), (v.lower(), None))

    def test_classify_exact(self):
        good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        self.assertEqual(si.classify(good.lower())[1], None)  # all-lowercase: no checksum to check
        self.assertEqual(si.classify("0x" + good[2:].upper())[1], None)  # all-uppercase: likewise
        self.assertEqual(si.classify(good[:-1] + "D")[1], "bad-checksum")  # one case flip
        self.assertEqual(si.classify(good[:-1])[1], "malformed")  # 39 hex digits
        self.assertEqual(si.classify(good + "0")[1], "malformed")
        self.assertEqual(si.classify("0X" + good[2:])[1], "malformed")
        self.assertEqual(si.classify(good[:10] + "g" + good[11:])[1], "malformed")
        self.assertEqual(si.classify("bc1qxyz")[1], "non-evm")
        self.assertEqual(si.classify("TXyz")[1], "non-evm")

    def test_abi_encoding(self):
        e = bytes(range(32))
        a = ["0x" + "11" * 20, "0x" + "22" * 20]
        cd = si.encode_block_batch(a, e)
        self.assertEqual(cd[:4].hex(), si.keccak256(b"blockBatch(address[],bytes32)")[:4].hex())
        words = [cd[4 + 32 * i : 36 + 32 * i] for i in range((len(cd) - 4) // 32)]
        self.assertEqual(int.from_bytes(words[0], "big"), 64)  # offset of the array
        self.assertEqual(words[1], e)
        self.assertEqual(int.from_bytes(words[2], "big"), 2)
        self.assertEqual(words[3][-20:].hex(), "11" * 20)
        self.assertEqual(words[4][-20:].hex(), "22" * 20)
        s = si.encode_set_status(a[0], 0, e)
        self.assertEqual(len(s), 4 + 96)

    def test_gas_model_is_an_upper_envelope(self):
        m = si.gas_model(ROOT / "results" / "batch_update.csv")
        import csv
        with open(ROOT / "results" / "batch_update.csv") as f:
            for r in csv.DictReader(f):
                if r["variant"] == "packed_unfunded":
                    self.assertGreaterEqual(m["fixed"] + m["perAddress"] * int(r["param"]), int(r["tx_gas"]))
        k = si.max_batch(m, 20_000, 0.10)
        self.assertLess(m["fixed"] + 20_000 + m["perAddress"] * k, si.TX_CAP * 0.9)
        self.assertGreaterEqual(m["fixed"] + 20_000 + m["perAddress"] * (k + 1), si.TX_CAP * 0.9)


# ============================================================================ sources
class Sources(Base):
    def test_two_formats_agree_and_skip_non_evm(self):
        evm = [fx.addr("s", i) for i in range(40)]
        code, out, err, m = self.build(self.pair("v1", evm))
        self.assertEqual(code, 0, err)
        self.assertEqual(m["addressCount"], 40)  # duplicates under two tickers counted once
        self.assertEqual(sorted(a.lower() for a in m["addresses"]), sorted(a.lower() for a in evm))
        prov = json.loads((self.tmp / "out" / "provenance.json").read_text())
        self.assertEqual({p["format"] for p in prov}, {"SDN_XML", "SDN_ADVANCED_XML"})
        self.assertTrue(all(p["nonEvmSkipped"] == 10 for p in prov))  # Tron-format USDT entries skipped
        self.assertEqual(m["publishDate"], "10/01/2026")

    def test_single_source_refused(self):
        evm = [fx.addr("s", i) for i in range(5)]
        src = self.pair("v1", evm)[:2]
        code, _, err, _ = self.build(src)
        self.assertEqual(code, 2)
        self.assertIn("at least 2", err)

    def test_disagreeing_sources_stop(self):
        evm = [fx.addr("s", i) for i in range(30)]
        a, _ = fx.write_pair(self.tmp / "x", fx.list_entries(evm, "x"), "10/01/2026")
        _, b = fx.write_pair(self.tmp / "y", fx.list_entries(evm[:-1], "x"), "10/01/2026")  # one address missing
        code, _, err, _ = self.build(["--source", str(a), "--source", str(b)])
        self.assertEqual(code, 2)
        self.assertIn("sources disagree", err)

    def test_bad_checksum_stops_build(self):
        evm = [fx.addr("s", i, checksum=True) for i in range(10)]
        good = evm[3]
        j = max(i for i, c in enumerate(good) if c.isalpha() and i > 1)  # last hex letter
        evm[3] = good[:j] + good[j].swapcase() + good[j + 1 :]  # one case flip: a typo EIP-55 catches
        code, _, err, _ = self.build(self.pair("v1", evm, dup_every=1000))
        self.assertEqual(code, 2)
        self.assertIn("bad-checksum", err)

    def test_malformed_stops_build(self):
        evm = [fx.addr("s", i) for i in range(10)]
        evm[0] = evm[0][:-2]
        code, _, err, _ = self.build(self.pair("v1", evm, dup_every=1000))
        self.assertEqual(code, 2)
        self.assertIn("malformed", err)

    def test_doctype_rejected(self):
        p = self.tmp / "evil.xml"
        p.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><sdnList/>')
        code, _, err, _ = self.build(["--source", str(p), "--source", str(p)])
        self.assertEqual(code, 2)
        self.assertIn("DOCTYPE", err)

    def test_http_refused(self):
        code, _, err, _ = self.build(["--source", "http://example.org/SDN.XML", "--source", "x"])
        self.assertEqual(code, 2)
        self.assertIn("non-HTTPS", err)

    def test_unknown_format(self):
        p = self.tmp / "x.xml"
        p.write_text("<other/>")
        code, _, err, _ = self.build(["--source", str(p), "--source", str(p)])
        self.assertEqual(code, 2)
        self.assertIn("unknown root", err)


# ============================================================================ review safeguards (A5)
class Safeguards(Base):
    def test_protected_address_in_list_stops(self):
        evm = [fx.addr("s", i) for i in range(10)]
        prot = self.tmp / "protect.json"
        prot.write_text(json.dumps([evm[4]]))
        code, _, err, _ = self.build(self.pair("v1", evm), "out", "--protect", str(prot))
        self.assertEqual(code, 2)
        self.assertIn("protected addresses", err)

    def test_look_alike_of_protected_address_warned(self):
        custody = si.to_checksum("0x" + "ab12" + "00" * 16 + "cd34")
        twin = "0x" + "ab12" + "77" * 16 + "cd34"  # same first/last four hex digits
        evm = [fx.addr("s", i) for i in range(5)] + [twin]
        prot = self.tmp / "protect.json"
        prot.write_text(json.dumps([custody]))
        code, _, err, m = self.build(self.pair("v1", evm), "out", "--protect", str(prot))
        self.assertEqual(code, 0, err)
        self.assertTrue(any(w.startswith("PROTECTED look-alike") and custody in w for w in m["warnings"]))
        self.assertIn(si.to_checksum(twin), m["diff"]["add"])  # exact match decides; the warning is for reviewers

    def test_rollback_to_older_list_refused(self):
        evm = [fx.addr("s", i) for i in range(10)]
        code, _, _, _ = self.build(self.pair("v2", evm, date="10/15/2026"), "applied")
        self.assertEqual(code, 0)
        prev = str(self.tmp / "applied" / "manifest.json")
        code, _, err, _ = self.build(self.pair("v1", evm[:5], date="10/01/2026"), "out", "--previous", prev)
        self.assertEqual(code, 2)
        self.assertIn("refusing rollback", err)

    def test_same_date_different_set_refused(self):
        evm = [fx.addr("s", i) for i in range(10)]
        self.build(self.pair("a", evm), "applied")
        code, _, err, _ = self.build(self.pair("b", evm[:9]), "out", "--previous", str(self.tmp / "applied" / "manifest.json"))
        self.assertEqual(code, 2)
        self.assertIn("same publish date", err)


# ============================================================================ diff and batching (A7)
class Batching(Base):
    def test_diff_against_applied_list(self):
        v1 = [fx.addr("s", i) for i in range(100)]
        self.build(self.pair("v1", v1), "v1")
        v2 = v1[5:] + [fx.addr("n", i) for i in range(20)]
        code, _, err, m = self.build(self.pair("v2", v2, date="10/15/2026"), "v2", "--previous", str(self.tmp / "v1" / "manifest.json"))
        self.assertEqual(code, 0, err)
        self.assertEqual(len(m["diff"]["add"]), 20)
        self.assertEqual(sorted(m["diff"]["remove"]), sorted(si.to_checksum(a) for a in v1[:5]))
        self.assertEqual(m["diff"]["unchanged"], 95)
        removals = [b for b in m["batches"] if b["function"].startswith("setStatus")]
        self.assertEqual(len(removals), 5)
        self.assertTrue(all(b["tier"] == "slow" and "review" in b for b in removals))
        prev_e = json.loads((self.tmp / "v1" / "manifest.json").read_text())["evidenceHash"]
        self.assertEqual(m["previousEvidenceHash"], prev_e)

    def test_batches_respect_cap_and_cover_all(self):
        evm = [fx.addr("s", i) for i in range(1500)]
        code, _, err, m = self.build(self.pair("v1", evm))
        self.assertEqual(code, 0, err)
        k = m["batching"]["maxAddressesPerBatch"]
        sizes = [len(b["addresses"]) for b in m["batches"]]
        self.assertEqual(sizes, [k, k, 1500 - 2 * k])
        self.assertTrue(all(b["estimatedTxGas"] < si.TX_CAP * 0.9 for b in m["batches"]))
        covered = [a for b in m["batches"] for a in b["addresses"]]
        self.assertEqual(len(covered), 1500)
        self.assertEqual(set(covered), set(m["addresses"]))
        e = m["evidenceHash"]
        self.assertTrue(all(b["evidenceHash"] == e and e[2:] in b["calldata"] for b in m["batches"]))

    def test_fast_budget_splits_tiers(self):
        evm = [fx.addr("s", i) for i in range(120)]
        code, _, err, m = self.build(self.pair("v1", evm), "out", "--fast-budget", "50", "--max-batch", "40")
        self.assertEqual(code, 0, err)
        self.assertEqual([(b["tier"], len(b["addresses"])) for b in m["batches"]],
                         [("fast", 40), ("fast", 10), ("slow", 40), ("slow", 30)])

    def test_evidence_hash_binds_list_version(self):
        evm = [fx.addr("s", i) for i in range(10)]
        _, _, _, m1 = self.build(self.pair("a", evm), "o1")
        _, _, _, m2 = self.build(self.pair("b", evm, non_evm=3), "o2")  # different bytes, same list
        _, _, _, m3 = self.build(self.pair("c", evm, date="10/02/2026"), "o3")
        self.assertEqual(m1["evidenceHash"], m2["evidenceHash"])
        self.assertNotEqual(m1["evidenceHash"], m3["evidenceHash"])


# ============================================================================ second reviewer
class Verify(Base):
    def test_independent_recomputation_matches(self):
        evm = [fx.addr("s", i) for i in range(30)]
        src = self.pair("v1", evm)
        self.build(src)
        # reviewer B retrieves the publication again (different bytes, same content)
        src_b = self.pair("v1b", evm, non_evm=4)
        code, out, err = run("verify", *src_b, "--manifest", str(self.tmp / "out" / "manifest.json"))
        self.assertEqual(code, 0, err)
        self.assertIn("MATCH", out)

    def test_tampered_manifest_detected(self):
        evm = [fx.addr("s", i) for i in range(30)]
        src = self.pair("v1", evm)
        self.build(src)
        p = self.tmp / "out" / "manifest.json"
        m = json.loads(p.read_text())
        b = m["batches"][0]
        b["calldata"] = b["calldata"][:-40] + "00" * 20  # swap the last address for 0x00..00
        p.write_text(json.dumps(m))
        code, _, err = run("verify", *src, "--manifest", str(p))
        self.assertEqual(code, 1)
        self.assertIn("MISMATCH in: batches", err)

    def test_different_parameters_detected(self):
        evm = [fx.addr("s", i) for i in range(30)]
        src = self.pair("v1", evm)
        self.build(src)
        code, _, err = run("verify", *src, "--manifest", str(self.tmp / "out" / "manifest.json"), "--max-batch", "7")
        self.assertEqual(code, 1)


# ============================================================================ on-chain check against a local node
@unittest.skipUnless(shutil.which("anvil") and shutil.which("forge") and shutil.which("cast"), "needs anvil, forge, cast")
class OnChain(Base):
    KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil default account 0
    ACCT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    @staticmethod
    def _free_port() -> str:
        """A port nothing listens on, so a node left over from an interrupted run (or any other
        service) can never answer in place of this test's own node."""
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return str(s.getsockname()[1])

    def setUp(self):
        super().setUp()
        port = self._free_port()
        # Same process group as the test, so Ctrl-C in a terminal stops the node too.
        self.node = subprocess.Popen(["anvil", "--port", port, "--silent"])
        self.addCleanup(self._stop_node)  # runs even if the rest of setUp fails
        self.rpc = f"http://127.0.0.1:{port}"
        for _ in range(100):
            if self.node.poll() is not None:
                self.fail(f"anvil exited with code {self.node.returncode} before it was ready")
            if subprocess.run(["cast", "chain-id", "--rpc-url", self.rpc], capture_output=True).returncode == 0:
                break
            time.sleep(0.1)
        else:
            self.fail("anvil did not become ready within 10 s")
        r = subprocess.run(
            ["forge", "create", "src/EnforcedToken.sol:EnforcedToken", "--rpc-url", self.rpc, "--private-key", self.KEY,
             "--broadcast", "--constructor-args", self.ACCT, "[]"],  # authority = account 0 (a plain key
            # for this test), no custody accounts
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.token = next(l.split()[-1] for l in r.stdout.splitlines() if "Deployed to" in l)

    def _stop_node(self):
        if self.node.poll() is None:
            self.node.terminate()
            try:
                self.node.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.node.kill()
                self.node.wait()

    def _block(self, a: str):
        r = subprocess.run(["cast", "send", self.token, "setStatus(address,uint8,bytes32)", a, "2", "0x" + "00" * 32,
                            "--rpc-url", self.rpc, "--private-key", self.KEY], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_drift_and_already_blocked_reported(self):
        v1 = [fx.addr("s", i) for i in range(6)]
        self.build(self.pair("v1", v1), "v1")
        for a in v1[1:]:
            self._block(a)  # v1 applied, except v1[0]: someone lifted (or never applied) it
        v2 = v1 + [fx.addr("n", 0), fx.addr("n", 1)]
        self._block(v2[-1])  # already blocked by a lawful order
        code, _, err, m = self.build(self.pair("v2", v2, date="10/15/2026"), "v2",
                                     "--previous", str(self.tmp / "v1" / "manifest.json"),
                                     "--rpc", self.rpc, "--token", self.token)
        self.assertEqual(code, 3, err)  # drift is an error the operator must look at
        report = (self.tmp / "v2" / "report.md").read_text()
        self.assertIn(f"DRIFT: {si.to_checksum(v1[0])}", report)
        self.assertIn(f"info: {si.to_checksum(v2[-1])} is already BLOCKED", report)
        self.assertEqual(len(m["diff"]["add"]), 2)  # batches do not depend on chain state

    def test_consistent_chain_passes(self):
        v1 = [fx.addr("s", i) for i in range(4)]
        self.build(self.pair("v1", v1), "v1")
        for a in v1:
            self._block(a)
        code, _, err, _ = self.build(self.pair("v1b", v1, non_evm=2), "v1b",
                                     "--previous", str(self.tmp / "v1" / "manifest.json"),
                                     "--rpc", self.rpc, "--token", self.token)
        self.assertEqual(code, 0, err)


if __name__ == "__main__":
    unittest.main()
