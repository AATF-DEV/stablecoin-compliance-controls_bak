# Requires: Foundry (forge), Python 3 with requirements.txt installed.
.PHONY: all build test tools ingest prove mutate bench data plot clean

all: test tools ingest prove mutate bench plot

build:
	forge build

# Correctness: unit tests + stateful invariant fuzzing
test:
	forge test --mc "Security|Invariants|Tiered|Bridge"

# Off-chain tooling: sanctions-list ingestion unit tests (on-chain checks use anvil)
tools:
	python3 -m unittest discover -s scripts/tests -v

# Ingestion demo: regenerate data/ingest/ and execute its actions on-chain (--isolate is REQUIRED)
ingest:
	python3 scripts/tests/make_demo.py
	forge test --isolate --mc "^Ingest$$" -vv

# Symbolic proofs: token invariants and tiered-authority properties (requires: pip install halmos==0.3.3).
# `forge clean` first: halmos needs AST-enabled build artifacts.
prove:
	forge clean && halmos --contract HalmosProofs && halmos --contract BridgedProofs && halmos --contract TieredProofs --loop 3

# Non-vacuity: inject bugs one at a time and require a Halmos counterexample for each.
mutate:
	python3 scripts/mutation_check.py

# Gas benchmarks. --isolate is REQUIRED: each top-level call is metered as its own transaction.
bench:
	forge test --isolate --mc Bench

# Regenerate SMT trees and proofs (~2 minutes for N = 1e5)
data:
	python3 scripts/gen_smt.py 1 10 100 1000 10000 100000

plot:
	python3 scripts/plot.py results

clean:
	forge clean
