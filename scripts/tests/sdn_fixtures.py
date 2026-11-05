"""Synthetic OFAC-format fixtures for testing scripts/sanctions_ingest.py.

The entries are invented (deterministic pseudo-random addresses, placeholder names); only the
XML structure follows OFAC's SDN.XML and SDN_ADVANCED.XML publications. No real SDN data is used.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sanctions_ingest as si  # noqa: E402

NS_XML = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML"
NS_ADV = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/ADVANCED_XML"
ALL_TICKERS = ("XBT", "ETH", "XMR", "ETC", "USDC", "USDT", "ARB", "BSC", "TRX", "SOL")


def addr(seed: str, i: int, checksum: bool | None = None) -> str:
    """Deterministic pseudo-random EVM address; checksum=None alternates EIP-55 and lowercase."""
    a = "0x" + hashlib.sha256(f"{seed}:{i}".encode()).hexdigest()[:40]
    use = (i % 2 == 0) if checksum is None else checksum
    return si.to_checksum(a) if use else a


def sdn_xml(entries: list[tuple[int, str, str]], date: str) -> bytes:
    """entries: (party uid, ticker, value). One <sdnEntry> per party uid."""
    by_party: dict[int, list[tuple[str, str]]] = {}
    for uid, t, v in entries:
        by_party.setdefault(uid, []).append((t, v))
    out = [f'<?xml version="1.0" standalone="yes"?>\n<sdnList xmlns="{NS_XML}">',
           f"<publshInformation><Publish_Date>{date}</Publish_Date><Record_Count>{len(by_party)}</Record_Count></publshInformation>"]
    n = 1
    for uid, ids in sorted(by_party.items()):
        out.append(f"<sdnEntry><uid>{uid}</uid><lastName>TEST ENTITY {uid}</lastName><sdnType>Entity</sdnType>"
                   f"<programList><program>TEST</program></programList><idList>")
        for t, v in ids:
            out.append(f"<id><uid>{n}</uid><idType>{escape(si.FEATURE_PREFIX + t)}</idType><idNumber>{escape(v)}</idNumber></id>")
            n += 1
        out.append("</idList></sdnEntry>")
    out.append("</sdnList>")
    return "\n".join(out).encode()


def sdn_advanced(entries: list[tuple[int, str, str]]) -> bytes:
    type_id = {t: str(340 + i) for i, t in enumerate(ALL_TICKERS)}
    out = [f'<?xml version="1.0" encoding="utf-8"?>\n<Sanctions xmlns="{NS_ADV}">',
           "<ReferenceValueSets><FeatureTypeValues>"]
    out += [f'<FeatureType ID="{type_id[t]}" FeatureTypeGroupID="1">{si.FEATURE_PREFIX}{t}</FeatureType>' for t in ALL_TICKERS]
    out.append('<FeatureType ID="8">Nationality Country</FeatureType></FeatureTypeValues></ReferenceValueSets><DistinctParties>')
    by_party: dict[int, list[tuple[str, str]]] = {}
    for uid, t, v in entries:
        by_party.setdefault(uid, []).append((t, v))
    fid = 1
    for uid, ids in sorted(by_party.items()):
        out.append(f'<DistinctParty FixedRef="{uid}"><Profile ID="{uid}" PartySubTypeID="4">')
        out.append(f'<Feature ID="{fid}" FeatureTypeID="8"><FeatureVersion ID="{fid}"><VersionDetail DetailTypeID="1430">XX</VersionDetail></FeatureVersion></Feature>')
        fid += 1
        for t, v in ids:
            out.append(f'<Feature ID="{fid}" FeatureTypeID="{type_id[t]}"><FeatureVersion ID="{fid}" ReliabilityID="1">'
                       f'<VersionDetail DetailTypeID="1432">{escape(v)}</VersionDetail></FeatureVersion></Feature>')
            fid += 1
        out.append("</Profile></DistinctParty>")
    out.append("</DistinctParties></Sanctions>")
    return "\n".join(out).encode()


def list_entries(evm: list[str], seed: str, non_evm: int = 10, dup_every: int = 50) -> list[tuple[int, str, str]]:
    """EVM addresses spread over EVM-format tickers, some listed twice (under ETH and USDT),
    plus non-EVM entries (XBT, and USDT on Tron) that must be skipped."""
    evm_tickers = ("ETH", "USDT", "USDC", "ETC", "ARB", "BSC")
    e = []
    for i, a in enumerate(evm):
        uid = 10_000 + i // 3  # a few addresses per party
        e.append((uid, evm_tickers[i % len(evm_tickers)], a))
        if i % dup_every == 0:
            e.append((uid, "ETH" if evm_tickers[i % len(evm_tickers)] != "ETH" else "USDT", a.lower()))
    for j in range(non_evm):
        h = hashlib.sha256(f"{seed}:nonevm:{j}".encode()).hexdigest()
        e.append((90_000 + j, "XBT", "bc1q" + h[:38]))
        e.append((90_000 + j, "USDT", "T" + h[:33]))  # Tron-format USDT entry
    return e


def write_pair(dirpath: Path, entries, date: str) -> tuple[Path, Path]:
    dirpath.mkdir(parents=True, exist_ok=True)
    a, b = dirpath / "SDN.XML", dirpath / "SDN_ADVANCED.XML"
    a.write_bytes(sdn_xml(entries, date))
    b.write_bytes(sdn_advanced(entries))
    return a, b
