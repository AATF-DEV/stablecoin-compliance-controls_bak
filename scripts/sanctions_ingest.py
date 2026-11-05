#!/usr/bin/env python3
"""Sanctions-list ingestion for EnforcedToken (paper, Section 5.3; adversaries A5 and A7).

Turns OFAC SDN list publications into reviewable, size-capped `blockBatch` actions, and lets a
second reviewer reproduce the result independently.

  build   Read two or more independently retrieved copies of the list (files or HTTPS URLs),
          extract EVM addresses, require that every copy yields the same set, validate each
          address exactly (EIP-55 when mixed-case; never similarity matching), diff against the
          previously applied manifest, check protected and look-alike addresses, and split the
          additions into batches below the EIP-7825 per-transaction gas cap. Writes
          manifest.json (the reviewable result, with each action's calldata), provenance.json and report.md.
  verify  Recompute the same result from the reviewer's own copies and compare it with a
          manifest. Exit code 0 only if the evidence hash, the address set, the diff and every
          batch are identical.

What this tool does NOT do: it signs nothing and submits nothing. Dual-control review of the
report, and the decision to sign, remain human steps (paper, Section 5.3).

Inputs it accepts: OFAC SDN.XML (root <sdnList>, entries <sdnEntry>/<idList>/<id> with
<idType>Digital Currency Address - ETH</idType><idNumber>0x...</idNumber>) and SDN_ADVANCED.XML
(root <Sanctions>; <FeatureType ID=...>Digital Currency Address - ETH</FeatureType> under
<ReferenceValueSets>, <Feature FeatureTypeID=...> with <VersionDetail>0x...</VersionDetail> under
<DistinctParties>). Namespaces are ignored. The default asset tickers are those whose addresses
share the EVM format; entries under them that are not EVM-format (e.g. USDT on Tron) are counted
and skipped, while a malformed 0x entry aborts the build.

Usage: see `python3 scripts/sanctions_ingest.py build -h` and the README.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from Crypto.Hash import keccak as _keccak  # pycryptodome (see requirements.txt)
except ImportError:  # pragma: no cover
    sys.exit("pycryptodome is required: pip install -r requirements.txt")

FORMAT = "stablecoin-compliance-ingest/1"
FEATURE_PREFIX = "Digital Currency Address - "
DEFAULT_ASSETS = ("ETH", "ETC", "USDC", "USDT", "ARB", "BSC")
TX_CAP = 2**24  # EIP-7825
MAX_SOURCE_BYTES = 512 * 1024 * 1024
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SEL_BLOCK_BATCH = "blockBatch(address[],bytes32)"
SEL_SET_STATUS = "setStatus(address,uint8,bytes32)"
SEL_STATUS_OF = "statusOf(address)"
ACTIVE, BLOCKED = 0, 2


class IngestError(Exception):
    """A condition that must stop the build until a human resolves it."""


# ----------------------------------------------------------------------------- primitives
def keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def selector(signature: str) -> bytes:
    return keccak256(signature.encode())[:4]


def to_checksum(addr: str) -> str:
    """EIP-55 checksum encoding of a 0x-prefixed address (any case)."""
    body = addr[2:].lower()
    h = keccak256(body.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(body))


def classify(raw: str) -> tuple[str | None, str | None]:
    """Return (canonical lowercase address, None), or (None, reason).

    reason is "non-evm" for entries that are not 0x-addresses (skipped), "malformed" or
    "bad-checksum" for entries that look like EVM addresses but are not valid (build aborts).
    Matching is exact: no trimming of inner characters, no similarity, no case folding of a
    mixed-case address that fails its checksum.
    """
    s = raw.strip()
    if not s.lower().startswith("0x"):
        return None, "non-evm"
    if not s.startswith("0x"):
        return None, "malformed"  # "0X" prefix is not a valid EVM address literal
    if not ADDR_RE.match(s):
        return None, "malformed"
    body = s[2:]
    if body != body.lower() and body != body.upper() and to_checksum(s) != s:
        return None, "bad-checksum"
    return "0x" + body.lower(), None


def look_alike_key(addr: str) -> str:
    """First and last four hex digits: the part people compare by eye (address poisoning)."""
    return addr[2:6].lower() + addr[-4:].lower()


# ----------------------------------------------------------------------------- sources
def read_source(spec: str) -> tuple[str, bytes]:
    """Read a file path or an https:// URL. TLS certificates are verified; plain http is refused."""
    if "://" in spec:
        if not spec.startswith("https://"):
            raise IngestError(f"refusing non-HTTPS source {spec}")
        req = urllib.request.Request(spec, headers={"User-Agent": "stablecoin-compliance-ingest/1"})
        with urllib.request.urlopen(req, timeout=120) as r:  # default SSL context verifies certificates
            data = r.read(MAX_SOURCE_BYTES + 1)
    else:
        data = Path(spec).read_bytes()
    if len(data) > MAX_SOURCE_BYTES:
        raise IngestError(f"{spec}: larger than {MAX_SOURCE_BYTES} bytes")
    head = data[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data.upper():
        raise IngestError(f"{spec}: DOCTYPE/ENTITY declarations are not accepted (XXE / entity expansion)")
    return spec, data


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(el: ET.Element, name: str) -> str | None:
    for c in el:
        if _local(c.tag) == name:
            return (c.text or "").strip()
    return None


def parse_sdn_xml(root: ET.Element, assets: set[str]) -> tuple[list[tuple[str, str]], str | None]:
    """SDN.XML: <sdnEntry><idList><id><idType/><idNumber/></id></idList></sdnEntry>."""
    out: list[tuple[str, str]] = []
    for entry in root.iter():
        if _local(entry.tag) != "sdnEntry":
            continue
        for el in entry.iter():
            if _local(el.tag) != "id":
                continue
            t = _child_text(el, "idType") or ""
            if t.startswith(FEATURE_PREFIX) and t[len(FEATURE_PREFIX):] in assets:
                out.append((t[len(FEATURE_PREFIX):], _child_text(el, "idNumber") or ""))
    date = None
    for el in root.iter():
        if _local(el.tag) == "Publish_Date":
            date = (el.text or "").strip()
            break
    return out, date


def parse_sdn_advanced(root: ET.Element, assets: set[str]) -> tuple[list[tuple[str, str]], str | None]:
    """SDN_ADVANCED.XML: FeatureType IDs by name, then Feature elements with that FeatureTypeID."""
    type_ids: dict[str, str] = {}
    for el in root.iter():
        if _local(el.tag) == "FeatureType":
            t = (el.text or "").strip()
            if t.startswith(FEATURE_PREFIX) and t[len(FEATURE_PREFIX):] in assets:
                type_ids[el.get("ID", "")] = t[len(FEATURE_PREFIX):]
    out: list[tuple[str, str]] = []
    for el in root.iter():
        if _local(el.tag) != "Feature":
            continue
        asset = type_ids.get(el.get("FeatureTypeID", ""))
        if asset is None:
            continue
        for vd in el.iter():
            if _local(vd.tag) == "VersionDetail":
                out.append((asset, (vd.text or "").strip()))
    return out, None


def parse_source(name: str, data: bytes, assets: set[str]) -> dict:
    root = ET.fromstring(data)
    kind = _local(root.tag)
    if kind == "sdnList":
        fmt, (raw, date) = "SDN_XML", parse_sdn_xml(root, assets)
    elif kind == "Sanctions":
        fmt, (raw, date) = "SDN_ADVANCED_XML", parse_sdn_advanced(root, assets)
    else:
        raise IngestError(f"{name}: unknown root element <{kind}>")
    addrs: set[str] = set()
    errors: list[str] = []
    non_evm = 0
    for asset, value in raw:
        a, why = classify(value)
        if a is not None:
            addrs.add(a)
        elif why == "non-evm":
            non_evm += 1
        else:
            errors.append(f"{name}: {why} {asset} entry {value!r}")
    return {
        "name": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "format": fmt,
        "entries": len(raw),
        "nonEvmSkipped": non_evm,
        "publishDate": date,
        "addresses": addrs,
        "errors": errors,
    }


def _date_key(d: str) -> tuple[int, int, int]:
    """OFAC Publish_Date is MM/DD/YYYY."""
    m, dd, y = (int(x) for x in d.split("/"))
    return (y, m, dd)


# ----------------------------------------------------------------------------- gas model and ABI
def gas_model(csv_path: Path, variant: str = "packed_unfunded", k_min: int = 500) -> dict:
    """Linear fit of measured blockBatch transaction gas over K >= k_min (paper, Table 5).

    The zero-balance ("unfunded") variant is the worst case: every address costs a
    zero-to-non-zero storage write.
    """
    pts = []
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            if r["variant"] == variant:
                pts.append((int(r["param"]), int(r["tx_gas"])))
    big = [p for p in pts if p[0] >= k_min]
    if len(big) < 2:
        raise IngestError(f"{csv_path}: not enough {variant} points for a fit")
    (k0, g0), (k1, g1) = min(big), max(big)
    slope = -(-(g1 - g0) // (k1 - k0))  # marginal cost per address, rounded up
    intercept = max(g - slope * k for k, g in pts)  # line lies on or above EVERY measured point
    return {"source": str(csv_path), "variant": variant, "perAddress": slope, "fixed": intercept}


def max_batch(model: dict, overhead: int, margin: float) -> int:
    budget = int(TX_CAP * (1 - margin)) - model["fixed"] - overhead
    return max(1, budget // model["perAddress"])


def _word(b: bytes) -> bytes:
    return b.rjust(32, b"\0")


def encode_block_batch(addrs: list[str], evidence: bytes) -> bytes:
    body = _word((64).to_bytes(32, "big")) + evidence + _word(len(addrs).to_bytes(32, "big"))
    body += b"".join(_word(bytes.fromhex(a[2:])) for a in addrs)
    return selector(SEL_BLOCK_BATCH) + body


def encode_set_status(addr: str, status: int, evidence: bytes) -> bytes:
    return selector(SEL_SET_STATUS) + _word(bytes.fromhex(addr[2:])) + _word(bytes([status])) + evidence


# ----------------------------------------------------------------------------- on-chain read (optional)
def rpc_status(rpc: str, token: str, addrs: list[str]) -> dict[str, int]:
    """statusOf(addr) for each address via eth_call (read-only)."""
    out = {}
    sel = selector(SEL_STATUS_OF).hex()
    for i, a in enumerate(addrs):
        payload = {
            "jsonrpc": "2.0",
            "id": i,
            "method": "eth_call",
            "params": [{"to": token, "data": "0x" + sel + a[2:].rjust(64, "0")}, "latest"],
        }
        req = urllib.request.Request(
            rpc, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read())
        if "error" in res:
            raise IngestError(f"RPC error for {a}: {res['error']}")
        out[a] = int(res["result"], 16)
    return out


# ----------------------------------------------------------------------------- core computation
def compute(
    sources: list[tuple[str, bytes]],
    previous: dict | None,
    protected: set[str],
    assets: tuple[str, ...],
    model: dict,
    overhead: int,
    margin: float,
    batch_cap: int | None,
    fast_budget: int | None,
    min_sources: int = 2,
) -> tuple[dict, list[dict]]:
    """Pure function of its inputs. Returns (manifest core, per-source provenance)."""
    if len(sources) < min_sources:
        raise IngestError(f"need at least {min_sources} independently retrieved sources, got {len(sources)}")
    parsed = [parse_source(n, d, set(assets)) for n, d in sources]
    errors = [e for p in parsed for e in p["errors"]]
    if errors:
        raise IngestError("invalid entries (fix or confirm with the publisher before proceeding):\n  " + "\n  ".join(errors))

    # independent copies must agree exactly
    ref = parsed[0]["addresses"]
    for p in parsed[1:]:
        if p["addresses"] != ref:
            only_a = sorted(ref - p["addresses"])[:10]
            only_b = sorted(p["addresses"] - ref)[:10]
            raise IngestError(
                f"sources disagree: {parsed[0]['name']} vs {p['name']}: "
                f"{len(ref - p['addresses'])} only in the first {only_a}, "
                f"{len(p['addresses'] - ref)} only in the second {only_b}"
            )
    dates = {p["publishDate"] for p in parsed if p["publishDate"]}
    if len(dates) > 1:
        raise IngestError(f"sources carry different publish dates: {sorted(dates)}")
    publish_date = dates.pop() if dates else None

    addrs = sorted(ref)
    list_hash = keccak256("\n".join(addrs).encode())
    version = {"format": FORMAT, "assets": list(assets), "publishDate": publish_date, "listHash": "0x" + list_hash.hex()}
    evidence = keccak256(json.dumps(version, sort_keys=True, separators=(",", ":")).encode())

    # rollback / staleness (A5): never accept an older publication than the one applied
    prev_set: set[str] = set()
    if previous is not None:
        prev_set = {a.lower() for a in previous["addresses"]}
        pd = previous.get("publishDate")
        if pd and publish_date and _date_key(publish_date) < _date_key(pd):
            raise IngestError(f"list published {publish_date} is older than the applied list ({pd}): refusing rollback")
        if pd and publish_date == pd and prev_set != set(addrs):
            raise IngestError(f"same publish date {pd} as the applied list but a different address set")

    add = sorted(set(addrs) - prev_set)
    remove = sorted(prev_set - set(addrs))

    # protected addresses (issuer custody, authority, bridges, ...) must never be restricted by a list update
    hit = sorted(set(addrs) & protected)
    if hit:
        raise IngestError("protected addresses appear in the list; resolve out of band: " + ", ".join(map(to_checksum, hit)))

    # look-alikes (A5): same first/last four hex digits as another relevant address
    warnings: list[str] = []
    known: dict[str, list[str]] = {}
    for a in sorted(prev_set | protected | set(addrs)):
        known.setdefault(look_alike_key(a), []).append(a)
    for a in add:
        others = [b for b in known[look_alike_key(a)] if b != a]
        if others:
            tag = "PROTECTED " if any(b in protected for b in others) else ""
            warnings.append(
                f"{tag}look-alike: {to_checksum(a)} shares first/last four hex digits with "
                + ", ".join(map(to_checksum, others))
            )

    # batching (A7): every transaction below the EIP-7825 cap with margin; fast tier up to its budget
    k_max = max_batch(model, overhead, margin)
    if batch_cap is not None:
        k_max = min(k_max, batch_cap)
    e_hex = "0x" + evidence.hex()
    batches: list[dict] = []
    fast_left = len(add) if fast_budget is None else fast_budget
    i = 0
    while i < len(add):
        tier = "fast" if fast_left > 0 else "slow"
        k = min(k_max, len(add) - i, fast_left if tier == "fast" else k_max)
        chunk = add[i : i + k]
        batches.append(
            {
                "tier": tier,
                "function": SEL_BLOCK_BATCH,
                "addresses": [to_checksum(a) for a in chunk],
                "calldata": "0x" + encode_block_batch(chunk, evidence).hex(),
                "estimatedTxGas": model["fixed"] + overhead + model["perAddress"] * k,
                "evidenceHash": e_hex,
            }
        )
        if tier == "fast":
            fast_left -= k
        i += k
    for a in remove:  # permissive: slow tier, one action each, human review required
        batches.append(
            {
                "tier": "slow",
                "function": SEL_SET_STATUS,
                "addresses": [to_checksum(a)],
                "calldata": "0x" + encode_set_status(a, ACTIVE, evidence).hex(),
                "estimatedTxGas": None,
                "evidenceHash": e_hex,
                "review": "delisted: confirm no lawful order or other case also restrains this address",
            }
        )
    for b in batches:
        if b["estimatedTxGas"] is not None and b["estimatedTxGas"] >= TX_CAP:
            raise IngestError("internal: batch estimate exceeds the transaction cap")

    core = {
        "format": FORMAT,
        "assets": list(assets),
        "publishDate": publish_date,
        "listHash": version["listHash"],
        "evidenceHash": e_hex,
        "previousEvidenceHash": previous["evidenceHash"] if previous else None,
        "addressCount": len(addrs),
        "addresses": [to_checksum(a) for a in addrs],
        "diff": {
            "add": [to_checksum(a) for a in add],
            "remove": [to_checksum(a) for a in remove],
            "unchanged": len(set(addrs) & prev_set),
        },
        "warnings": warnings,
        "batching": {
            "txCap": TX_CAP,
            "margin": margin,
            "authorityOverhead": overhead,
            "gasModel": {k: model[k] for k in ("variant", "perAddress", "fixed")},
            "maxAddressesPerBatch": k_max,
            "fastBudget": fast_budget,
        },
        "batches": batches,
    }
    provenance = [{k: p[k] for k in ("name", "sha256", "bytes", "format", "entries", "nonEvmSkipped", "publishDate")} for p in parsed]
    return core, provenance


# ----------------------------------------------------------------------------- report
def render_report(core: dict, provenance: list[dict], chain: dict | None) -> str:
    L = []
    L.append(f"# Sanctions list update for review\n")
    L.append(f"- Evidence hash (on-chain `e`): `{core['evidenceHash']}`")
    L.append(f"- List hash: `{core['listHash']}`; publish date: {core['publishDate'] or 'n/a'}; assets: {', '.join(core['assets'])}")
    L.append(f"- Previous evidence hash: `{core['previousEvidenceHash']}`")
    L.append(f"- Addresses: {core['addressCount']} (+{len(core['diff']['add'])} / -{len(core['diff']['remove'])} / ={core['diff']['unchanged']})\n")
    L.append("## Sources (all yield the same address set)\n")
    L.append("| Source | Format | SHA-256 | Entries | Non-EVM skipped |\n|---|---|---|---:|---:|")
    for p in provenance:
        L.append(f"| {p['name']} | {p['format']} | `{p['sha256']}` | {p['entries']} | {p['nonEvmSkipped']} |")
    L.append("\n## Warnings\n")
    L += [f"- {w}" for w in core["warnings"]] or ["- none"]
    if chain is not None:
        L.append("\n## On-chain state (read-only check)\n")
        L += [f"- {line}" for line in chain["lines"]] or ["- consistent with the previous manifest"]
    L.append("\n## Actions\n")
    L.append(f"Max {core['batching']['maxAddressesPerBatch']} addresses per batch "
             f"(cap 2^24, margin {core['batching']['margin']:.0%}, model {core['batching']['gasModel']}).\n")
    L.append("| # | Tier | Function | Addresses | Est. tx gas |\n|---:|---|---|---:|---:|")
    for i, b in enumerate(core["batches"]):
        L.append(f"| {i} | {b['tier']} | `{b['function']}` | {len(b['addresses'])} | {b['estimatedTxGas'] or 'n/a'} |")
    L.append("\n## Additions\n")
    L += [f"- `{a}`" for a in core["diff"]["add"]] or ["- none"]
    L.append("\n## Removals (slow tier; check each against open cases before signing)\n")
    L += [f"- `{a}`" for a in core["diff"]["remove"]] or ["- none"]
    L.append("\n## Second reviewer\n")
    L.append("Fetch the sources yourself and run `sanctions_ingest.py verify` against this manifest. "
             f"Sign only if it reports a match for evidence hash `{core['evidenceHash']}`.")
    return "\n".join(L) + "\n"


def chain_check(rpc: str, token: str, core: dict, previous: dict | None) -> dict:
    prev = [a.lower() for a in previous["addresses"]] if previous else []
    add = [a.lower() for a in core["diff"]["add"]]
    st = rpc_status(rpc, token, sorted(set(prev) | set(add)))
    lines = []
    for a in prev:
        if st[a] != BLOCKED:
            lines.append(f"DRIFT: {to_checksum(a)} is in the applied list but its on-chain status is {st[a]}, not BLOCKED")
    for a in add:
        if st[a] == BLOCKED:
            lines.append(f"info: {to_checksum(a)} is already BLOCKED on-chain (e.g. by a lawful order)")
    return {"rpc": rpc, "token": token, "drift": any(l.startswith("DRIFT") for l in lines), "lines": lines}


# ----------------------------------------------------------------------------- CLI
def _load_json(p: str | None) -> dict | None:
    return json.loads(Path(p).read_text()) if p else None


def _protected(p: str | None) -> set[str]:
    if not p:
        return set()
    out = set()
    for raw in json.loads(Path(p).read_text()):
        a, why = classify(raw)
        if a is None:
            raise IngestError(f"protected list: {why} entry {raw!r}")
        out.add(a)
    return out


def _params(ns) -> dict:
    return dict(
        assets=tuple(ns.assets),
        model=gas_model(Path(ns.gas_model)),
        overhead=ns.authority_overhead,
        margin=ns.margin,
        batch_cap=ns.max_batch,
        fast_budget=ns.fast_budget,
        min_sources=ns.min_sources,
    )


def cmd_build(ns) -> int:
    previous = _load_json(ns.previous)
    core, prov = compute([read_source(s) for s in ns.source], previous, _protected(ns.protect), **_params(ns))
    chain = chain_check(ns.rpc, ns.token, core, previous) if ns.rpc else None
    out = Path(ns.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(json.dumps(core, indent=1, sort_keys=True) + "\n")
    (out / "provenance.json").write_text(json.dumps(prov, indent=1) + "\n")
    (out / "report.md").write_text(render_report(core, prov, chain))
    print(f"evidence hash {core['evidenceHash']}: +{len(core['diff']['add'])} -{len(core['diff']['remove'])}, "
          f"{len(core['batches'])} actions, {len(core['warnings'])} warnings -> {out}/")
    if chain and chain["drift"]:
        print("on-chain state has drifted from the applied list; see report.md", file=sys.stderr)
        return 3
    return 0


def cmd_verify(ns) -> int:
    claimed = json.loads(Path(ns.manifest).read_text())
    core, _ = compute([read_source(s) for s in ns.source], _load_json(ns.previous), _protected(ns.protect), **_params(ns))
    mine = json.dumps(core, sort_keys=True)
    theirs = json.dumps(claimed, sort_keys=True)
    if mine == theirs:
        print(f"MATCH evidence hash {core['evidenceHash']} ({len(core['batches'])} actions)")
        return 0
    diffs = [k for k in sorted(set(core) | set(claimed)) if core.get(k) != claimed.get(k)]
    print(f"MISMATCH in: {', '.join(diffs)}", file=sys.stderr)
    print(f"  recomputed evidence hash {core['evidenceHash']}, manifest says {claimed.get('evidenceHash')}", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("build", "verify"):
        p = sub.add_parser(name)
        p.add_argument("--source", action="append", required=True, help="file path or https:// URL; repeat (>= 2)")
        p.add_argument("--previous", help="manifest.json of the list currently applied on-chain")
        p.add_argument("--protect", help="JSON array of addresses that must never be restricted by a list update")
        p.add_argument("--assets", nargs="+", default=list(DEFAULT_ASSETS))
        p.add_argument("--gas-model", default=str(Path(__file__).resolve().parent.parent / "results" / "batch_update.csv"))
        p.add_argument("--authority-overhead", type=int, default=100_000,
                       help="gas on top of the measured 2-of-3 blockBatch model: the TieredAuthority fast tier "
                            "(~19,400 measured) plus first-use initialisation of the nonce, budget and log slots "
                            "on a fresh deployment (~68,000 measured), rounded up; see test/Ingest.t.sol")
        p.add_argument("--margin", type=float, default=0.10, help="fraction of the 2^24 cap kept free")
        p.add_argument("--max-batch", type=int, help="additional cap on addresses per batch")
        p.add_argument("--fast-budget", type=int, help="accounts the fast tier may still restrain this epoch")
        p.add_argument("--min-sources", type=int, default=2)
        if name == "build":
            p.add_argument("--out", required=True)
            p.add_argument("--rpc", help="JSON-RPC URL for a read-only on-chain status check")
            p.add_argument("--token", help="token address for --rpc")
        else:
            p.add_argument("--manifest", required=True)
    ns = ap.parse_args(argv)
    try:
        return cmd_build(ns) if ns.cmd == "build" else cmd_verify(ns)
    except IngestError as e:
        print(f"STOP: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
