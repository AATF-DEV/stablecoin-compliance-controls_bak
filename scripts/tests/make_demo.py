#!/usr/bin/env python3
"""Deterministic demo of the ingestion pipeline, used by the on-chain integration test (test/Ingest.t.sol).

v1: 1,000 synthetic EVM addresses (plus non-EVM entries that are skipped), first application.
v2: v1 minus 5 delisted addresses plus 300 new ones, one of which shares its first and last four
    hex digits with a protected custody address (flagged for reviewers, still matched exactly).

Writes data/ingest/{v1,v2}/{manifest.json,batches.json,provenance.json,report.md} and
data/ingest/protect.json. The XML sources are regenerated in a temporary directory; nothing here
is real SDN data. Run from the repository root: python3 scripts/tests/make_demo.py
"""
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import sanctions_ingest as si  # noqa: E402
import sdn_fixtures as fx  # noqa: E402

OUT = Path("data/ingest")
CUSTODY = si.to_checksum("0x" + "c057" + "00" * 16 + "0001")  # issuer custody (example)
BRIDGE = si.to_checksum("0x" + "b41d" + "00" * 16 + "0002")  # bridge adapter (example)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    protect = OUT / "protect.json"
    protect.write_text(json.dumps([CUSTODY, BRIDGE], indent=1) + "\n")
    v1 = [fx.addr("demo-v1", i) for i in range(1000)]
    twin = "0x" + "c057" + "5a" * 16 + "0001"  # look-alike of CUSTODY
    v2 = v1[5:] + [fx.addr("demo-v2", i) for i in range(299)] + [twin]
    with tempfile.TemporaryDirectory() as tmp:
        a1, b1 = fx.write_pair(Path(tmp) / "v1", fx.list_entries(v1, "demo-v1"), "10/01/2026")
        a2, b2 = fx.write_pair(Path(tmp) / "v2", fx.list_entries(v2, "demo-v2"), "10/15/2026")
        common = ["--protect", str(protect)]
        if si.main(["build", "--source", str(a1), "--source", str(b1), "--out", str(OUT / "v1"), *common]):
            return 1
        if si.main(["build", "--source", str(a2), "--source", str(b2), "--out", str(OUT / "v2"),
                    "--previous", str(OUT / "v1" / "manifest.json"), *common]):
            return 1
    for v in ("v1", "v2"):  # provenance names temporary paths; keep only what is reproducible
        p = OUT / v / "provenance.json"
        prov = json.loads(p.read_text())
        for s in prov:
            s["name"] = Path(s["name"]).name
        p.write_text(json.dumps(prov, indent=1) + "\n")
        r = OUT / v / "report.md"
        r.write_text(r.read_text().replace(str(Path(tmp)), "<tmp>"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
