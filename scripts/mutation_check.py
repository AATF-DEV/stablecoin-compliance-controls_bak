#!/usr/bin/env python3
"""Non-vacuity check for the Halmos proofs.

Injects bugs one at a time (ten into src/EnforcedToken.sol, ten into src/BridgedEnforcedToken.sol,
twenty-one into src/TieredAuthority.sol),
runs the relevant Halmos check, and requires a counterexample. The original sources are always
restored, even on error.

Usage: python3 scripts/mutation_check.py      (from the repository root; ~15 min)
Exit code 0 iff every mutant is killed.
"""
import re
import subprocess
import sys
from pathlib import Path

# (source file, Halmos contract, extra Halmos flags)
TOKEN = (Path("src/EnforcedToken.sol"), "HalmosProofs", ())
BRIDGED = (Path("src/BridgedEnforcedToken.sol"), "BridgedProofs", ())
AUTH = (Path("src/TieredAuthority.sol"), "TieredProofs", ("--loop", "3"))

MUTANTS = [
    (TOKEN, "frozen sender may transfer", "check_transfer",
     "if (f.status != ACTIVE) revert Restricted(from);",
     "if (f.status == BLOCKED) revert Restricted(from);"),
    (TOKEN, "seize does not reduce held", "check_seize",
     "x.held -= uint120(amt);", ""),
    (TOKEN, "burn does not reduce supply", "check_burnFromHold",
     "totalSupply -= amt;", ""),
    (TOKEN, "hold not bounded by spendable balance", "check_placeHold",
     "if (uint256(x.held) + amt > x.balance) revert HoldExceedsSpendable();", ""),
    (TOKEN, "seize deletes a different hold record", "check_seize",
     "if (h.amount == 0) delete holds[id];",
     "if (h.amount == 0) delete holds[bytes32(uint256(id) + 1)];"),
    (TOKEN, "blockBatch wipes the account's balance", "check_blockBatch",
     "_acct[accounts[i]].status = BLOCKED;",
     "_acct[accounts[i]] = Account(0, 0, BLOCKED);"),
    (TOKEN, "ordinary transfer advances the compliance log", "check_transfer",
     "        emit Transfer(from, to, amt);\n    }\n\n    // ================================================================ compliance actions",
     "        logCount += 1;\n        emit Transfer(from, to, amt);\n    }\n\n    // ================================================================ compliance actions"),
    (TOKEN, "blockBatch callable without the authority", "check_onlyAuthority",
     "function blockBatch(address[] calldata accounts, bytes32 evidenceHash) external onlyAuthority {",
     "function blockBatch(address[] calldata accounts, bytes32 evidenceHash) external {"),
    (TOKEN, "seizure logged without its evidence hash", "check_seize",
     "_log(A_SEIZE, keccak256(abi.encode(id, amt, dest)), evidenceHash);",
     "_log(A_SEIZE, keccak256(abi.encode(id, amt, dest)), bytes32(0));"),
    (TOKEN, "release logged under the wrong action tag", "check_releaseHold",
     "_log(A_RELEASE, keccak256(abi.encode(id)), evidenceHash);",
     "_log(A_HOLD, keccak256(abi.encode(id)), evidenceHash);"),
    # ---- BridgedEnforcedToken (ERC-7281 bridge interface, Sections 4.1 and 5.6)
    (BRIDGED, "frozen holder can bridge out", "check_bridgeBurn",
     "if (u.status != ACTIVE) revert Restricted(user);",
     "if (u.status == BLOCKED) revert Restricted(user);"),
    (BRIDGED, "held value can bridge out", "check_bridgeBurn",
     "if (uint256(u.balance) - u.held < amt) revert InsufficientSpendable();",
     "if (u.balance < amt) revert InsufficientSpendable();"),
    (BRIDGED, "bridge-out ignores the burning limit", "check_bridgeBurn",
     "        _use(l, amt);\n        unchecked {", "        unchecked {"),
    (BRIDGED, "a blocked bridge can burn", "check_bridgeBurn",
     "if (_acct[msg.sender].status == BLOCKED) revert Restricted(msg.sender); // a blocked bridge is shut", ""),
    (BRIDGED, "bridge-in ignores the minting limit", "check_bridgeMint",
     "            _use(l, amt);\n        }\n        Account storage t", "        }\n        Account storage t"),
    (BRIDGED, "bridge-in to a blocked account", "check_bridgeMint",
     "        if (t.status == BLOCKED) revert Restricted(to);\n        uint256 nb", "        uint256 nb"),
    (BRIDGED, "limits settable by anyone", "check_setLimits",
     "        external\n        onlyAuthority\n    {", "        external\n    {"),
    (BRIDGED, "limit change not logged", "check_setLimits",
     "        _log(A_LIMITS, keccak256(abi.encode(bridge, mintingLimit, burningLimit)), evidenceHash);\n", ""),
    (BRIDGED, "lowering a limit keeps the old available value", "check_setLimits",
     "nc = c > d ? c - d : 0;", "nc = c;"),
    (BRIDGED, "a blocked bridge can mint", "check_bridgeMint",
     "            if (_acct[msg.sender].status == BLOCKED) revert Restricted(msg.sender);\n            _use(l, amt);",
     "            _use(l, amt);"),
    # ---- TieredAuthority (Section 5.5)
    (AUTH, "fast tier accepts raising a bridge limit", "check_fastBridgeLimits",
     "return (m <= tk.mintingMaxLimitOf(b) && u <= tk.burningMaxLimitOf(b)) ? 1 : 0;", "return 1;"),
    (AUTH, "fast tier checks only the minting limit", "check_fastBridgeLimits",
     "return (m <= tk.mintingMaxLimitOf(b) && u <= tk.burningMaxLimitOf(b)) ? 1 : 0;",
     "return m <= tk.mintingMaxLimitOf(b) ? 1 : 0;"),
    (AUTH, "fast tier accepts a loosening status change", "check_fastOnlyRestricts",
     "return (s <= BLOCKED && s > IEnforcedToken(target).statusOf(a)) ? 1 : 0;",
     "return s <= BLOCKED ? 1 : 0;"),
    (AUTH, "fast tier accepts releaseHold", "check_fastOnlyRestricts",
     "if (sel == IEnforcedToken.placeHold.selector) return 1;",
     "if (sel == IEnforcedToken.placeHold.selector || sel == bytes4(keccak256(\"releaseHold(bytes32,bytes32)\"))) return 1;"),
    (AUTH, "fast tier accepts any target", "check_fastRejectsOthers",
     "if (target != token || target == address(0) || data.length < 4) return 0;",
     "if (data.length < 4) return 0;"),
    (AUTH, "fast-tier budget not enforced", "check_fastOnlyRestricts",
     "if (r > p.restrictBudget || v > p.valueBudget) revert BudgetExceeded();",
     "if (v > p.valueBudget) revert BudgetExceeded();"),
    (AUTH, "value budget not enforced", "check_valueBudget",
     "if (r > p.restrictBudget || v > p.valueBudget) revert BudgetExceeded();",
     "if (r > p.restrictBudget) revert BudgetExceeded();"),
    (AUTH, "queue accepts the fast-tier quorum", "check_queue",
     "address[] memory who = _quorum(id, sigs, p.mI, p.rolesI);",
     "address[] memory who = _quorum(id, sigs, p.mR, p.rolesR);"),
    (AUTH, "queued action executes before its delay", "check_executeQueued",
     "if (block.timestamp < when) revert TooEarly();", ""),
    (AUTH, "queued action can execute twice", "check_executeQueued",
     "        delete eta[id];\n        _spend(policy, 0, irreversibleValue(target, data));",
     "        _spend(policy, 0, irreversibleValue(target, data));"),
    (AUTH, "cancel does not clear the queue slot", "check_cancel",
     "        delete eta[id];\n        emit Cancelled(id, who);",
     "        emit Cancelled(id, who);"),
    (AUTH, "cancel ignores the guardian threshold", "check_cancel",
     "_guardianQuorum(cancelDigest(id), gsigs, policy.gThreshold);",
     "_guardianQuorum(cancelDigest(id), gsigs, 0);"),
    (AUTH, "configuration callable by anyone", "check_configOnlySelf",
     "if (msg.sender != address(this)) revert OnlySelf();", ""),
    (AUTH, "policy allows M_i = M_r", "check_configKeepsPolicy",
     "p.mR == 0 || p.mI <= p.mR ||", "p.mR == 0 || p.mI < p.mR ||"),
    (AUTH, "a guardian can become a signer", "check_configKeepsPolicy",
     "signers[s].active || isGuardian[s] || role >= MAX_ROLES",
     "signers[s].active || role >= MAX_ROLES"),
    (AUTH, "blockBatch charged as one account", "check_fastOnlyRestricts",
     "            return uint256(bytes32(data[4 + off:36 + off]));",
     "            return 1;"),
    (AUTH, "value budget counts only the bound token", "check_valueBudget",
     "function irreversibleValue(address, bytes calldata data) public pure returns (uint256) {\n        if (data.length < 4) return 0;",
     "function irreversibleValue(address target, bytes calldata data) public view returns (uint256) {\n        if (target != token || data.length < 4) return 0;"),
    (AUTH, "removeSigner does not decrement signerCount", "check_configBookkeeping",
     "        signerCount -= 1;\n        if (--_roleCount", "        if (--_roleCount"),
    (AUTH, "removeSigner does not update role counts", "check_configBookkeeping",
     "        if (--_roleCount[x.role] == 0) distinctRoles -= 1;\n", ""),
    (AUTH, "removeSigner does not deactivate the signer", "check_configBookkeeping",
     "        delete signers[s];\n", ""),
    (AUTH, "removeGuardian does not decrement guardianCount", "check_configBookkeeping",
     "        guardianCount -= 1;\n        emit GuardianRemoved", "        emit GuardianRemoved"),
]


def halmos(contract: str, function: str, flags) -> str:
    subprocess.run(["forge", "clean"], check=True, capture_output=True)
    r = subprocess.run(["halmos", "--contract", contract, "--function", function, *flags],
                       capture_output=True, text=True)
    out = re.sub(r"\x1b\[[0-9;]*m", "", r.stdout + r.stderr)
    if "Build failed" in out or "0 passed; 0 failed" in out:
        raise RuntimeError(f"halmos did not run {function}:\n{out[-2000:]}")
    return out


def main() -> int:
    # optional: a substring filter on mutant names, e.g. `mutation_check.py budget`
    only = sys.argv[1] if len(sys.argv) > 1 else None
    originals = {path: path.read_text() for path, _, _ in (TOKEN, BRIDGED, AUTH)}
    selected = [m for m in MUTANTS if only is None or only in m[1]]
    if not selected:
        print(f"no mutant matches {only!r}")
        return 2
    killed = 0
    try:
        for (path, contract, flags), name, fn, old, new in selected:
            original = originals[path]
            if original.count(old) != 1:
                print(f"[ERROR] pattern for '{name}' not found exactly once")
                return 2
            path.write_text(original.replace(old, new, 1))
            out = halmos(contract, fn, flags)
            path.write_text(original)
            ok = "Counterexample" in out or "[FAIL]" in out
            killed += ok
            print(f"[{'KILLED' if ok else 'SURVIVED'}] {name}  ({fn})")
    finally:
        for path, text in originals.items():
            path.write_text(text)
        subprocess.run(["forge", "clean"], capture_output=True)
    print(f"{killed}/{len(selected)} mutants killed")
    return 0 if killed == len(selected) else 1


if __name__ == "__main__":
    sys.exit(main())
