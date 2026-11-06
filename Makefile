# Requires: Foundry v1.5.1 (forge, anvil, cast), Python 3.10+ with requirements.txt installed,
# and Halmos 0.3.3 for `prove` and `mutate`. See README, "Step by step".
.PHONY: all build test tools ingest prove mutate bench data report timing plot reproduce clean

# Where `make plot` writes the figure; e.g. `make plot PLOT_DIR=../paper/figures` for the paper.
PLOT_DIR ?= results

# Solver threads for Halmos (`prove`, `mutate`). Default: the cores this process may use (CPU affinity,
# capped by a cgroup CPU quota), detected by scripts/timed.py. Override with e.g. `make prove THREADS=2`.
ifeq ($(origin THREADS),undefined)
THREADS := $(shell python3 scripts/timed.py --cores)
endif
HALMOS = halmos --solver-threads $(THREADS)
# Mutants to run: I/N runs every N-th mutant starting at index I (CI: SHARD=0/6 ... 5/6).
SHARD ?= 0/1
MUTATE_LABEL = mutation$(if $(filter-out 0/1,$(SHARD)),_shard$(subst /,of,$(SHARD)))

all: test tools ingest prove mutate bench report timing plot

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
# `forge clean` first: halmos needs AST-enabled build artifacts. Each suite is timed by scripts/timed.py,
# which writes results/timing/halmos_*.json (wall and CPU time, cores available and used, per-check times).
prove:
	forge clean
	python3 scripts/timed.py halmos_token --threads $(THREADS) -- $(HALMOS) --contract HalmosProofs
	python3 scripts/timed.py halmos_bridged --threads $(THREADS) -- $(HALMOS) --contract BridgedProofs
	python3 scripts/timed.py halmos_tiered --threads $(THREADS) -- $(HALMOS) --contract TieredProofs --loop 3

# Non-vacuity: inject bugs one at a time and require a Halmos counterexample for each.
# Timed into results/timing/$(MUTATE_LABEL).json, with every mutant's time.
mutate:
	python3 scripts/timed.py $(MUTATE_LABEL) --threads $(THREADS) -- \
		python3 scripts/mutation_check.py --shard $(SHARD) --solver-threads $(THREADS)

# Gas benchmarks. --isolate is REQUIRED: each top-level call is metered as its own transaction.
bench:
	forge test --isolate --mc Bench

# Regenerate SMT trees and proofs (~2 minutes for N = 1e5)
data:
	python3 scripts/gen_smt.py 1 10 100 1000 10000 100000

# Paper tables and derived figures from results/*.csv -> results/summary.md
report:
	python3 scripts/summarize.py

# Timing of the proofs and the mutation check, from results/timing/*.json -> results/timing/summary.md
# and results/timing/caption.tex (the sentence for the paper's Halmos table). Not part of `reproduce`.
timing:
	python3 scripts/timing_report.py

# Figure 2 of the paper: compliance_gas_benchmark.{pdf,png} from results/*.csv
plot:
	python3 scripts/plot.py $(PLOT_DIR)

# What CI's reproduce job runs: regenerate every committed result and fail unless all are identical.
reproduce: test tools ingest bench data report
	git diff --exit-code -- results data
	test -z "$$(git status --porcelain --untracked-files=all -- results data)"
	@echo "All committed results and data reproduced exactly."

clean:
	forge clean
