#!/usr/bin/env python3
"""Plot measured gas from results/*.csv (produced by `forge test --isolate --mc Bench`).

Usage: python3 scripts/plot.py <output_dir>
Every number drawn here is read from the CSVs; nothing is hard-coded.
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results"
TX_CAP = 2 ** 24

# Fixed entity -> color (validated categorical slots 1-5 + neutral gray), never by rank.
C = {"packed": "#2a78d6", "mapping": "#eb6834", "smt": "#1baf7a", "naive": "#c98500", "aggregate": "#8a5cc2",
     "base": "#6b6a66"}
INK, INK2 = "#0b0b0b", "#52514e"


def load(name):
    d = defaultdict(list)
    with open(ROOT / "results" / name) as f:
        for r in csv.DictReader(f):
            d[r["variant"]].append((int(r["param"]), int(r["tx_gas"])))
    return {k: sorted(v) for k, v in d.items()}


plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 8, "axes.titlesize": 8.5, "axes.labelsize": 8,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 6.8,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False, "lines.linewidth": 1.6, "lines.markersize": 4,
})

fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(7.2, 2.55), dpi=300)
for ax in (a1, a2, a3):
    ax.grid(True, which="major", color="#e4e3df", lw=0.6)
    ax.set_axisbelow(True)

# (a) per-transfer vs active holds -------------------------------------------------
t = load("transfer_holds.csv")
ks = [k for k, _ in t["naive_holds"]]
base = t["baseline"][0][1]
bl = t["blacklist_mapping"][0][1]
a1.plot(ks, [base] * len(ks), ls=":", color=C["base"], label="ERC-20 baseline")
a1.plot(ks, [bl] * len(ks), ls="--", color=C["mapping"], label="Blacklist mapping (no holds)")
a1.plot(*zip(*t["separate_aggregate"]), marker="D", ms=3, color=C["aggregate"],
        label="Separate status + aggregate held")
a1.plot(*zip(*t["naive_holds"]), marker="^", color=C["naive"], label="Naive: status + hold array")
a1.plot(*zip(*t["enforced_packed"]), marker="o", color=C["packed"], label="Packed slot (this work)")
a1.set_xlabel("Active holds on sender $k$")
a1.set_ylabel("Transaction gas")
a1.set_title("(a) Transfer cost vs. holds")
a1.set_ylim(0, 120000)
a1.yaxis.set_major_formatter(lambda v, _: f"{v/1000:.0f}k")
a1.legend(loc="upper left", frameon=False)

# (b) SMT transfer vs restricted-set size ------------------------------------------
s = load("smt_transfer.csv")["smt_proofs"]
ns = [n for n, _ in s]
packed = t["enforced_packed"][0][1]
a2.plot(ns, [g for _, g in s], marker="s", color=C["smt"], label="SMT proofs (sender + recipient)")
a2.plot(ns, [packed] * len(ns), marker="o", color=C["packed"], label="Packed slot (this work)")
a2.plot(ns, [base] * len(ns), ls=":", color=C["base"], label="ERC-20 baseline")
a2.set_xscale("log")
a2.set_xlabel("Restricted addresses $N$")
a2.set_title("(b) SMT transfer cost vs. list size")
a2.set_ylim(0, 90000)
a2.yaxis.set_major_formatter(lambda v, _: f"{v/1000:.0f}k")
a2.legend(loc="upper left", frameon=False)

# (c) list update vs batch size ----------------------------------------------------
b = load("batch_update.csv")
a3.plot(*zip(*b["mapping"]), marker="o", color=C["mapping"], label="Separate mapping")
a3.plot(*zip(*b["packed_unfunded"]), marker="o", ls="--", color=C["packed"], mfc="white",
        label="Packed, zero-bal. targets")
a3.plot(*zip(*b["packed_funded"]), marker="o", color=C["packed"], label="Packed, funded targets")
a3.plot(*zip(*b["smt_root"]), marker="s", color=C["smt"], label="SMT root (on-chain only)")
a3.axhline(TX_CAP, color=C["base"], ls=":", lw=1.2, label="EIP-7825 per-tx cap")
a3.set_xscale("log")
a3.set_yscale("log")
a3.set_ylim(3e4, 5e9)
a3.set_xlabel("Batch size $K$")
a3.set_title("(c) List update cost (2-of-3)")
a3.legend(loc="upper left", frameon=False, handlelength=1.8)

plt.tight_layout(w_pad=1.2)
OUT.mkdir(parents=True, exist_ok=True)
plt.savefig(OUT / "compliance_gas_benchmark.pdf", metadata={"CreationDate": None})  # reproducible bytes
plt.savefig(OUT / "compliance_gas_benchmark.png", dpi=200)
print("written to", OUT)
