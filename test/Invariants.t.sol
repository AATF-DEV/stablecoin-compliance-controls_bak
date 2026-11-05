// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";

/// Random-sequence driver. The handler itself is the token's `authority`, so the fuzzer
/// can interleave user transfers with every compliance action and ghost-track expected state.
contract Handler is Test {
    EnforcedToken public t;
    address[] public actors;
    bytes32[] public holdIds;
    mapping(bytes32 => bool) public everCreated;

    // ghosts
    mapping(address => uint256) public ghostHeld;
    uint256 public ghostMinted;
    uint256 public ghostBurned;
    uint256 public ghostActions;
    bytes32 public ghostHead;
    bool public frozenOutflowViolation;
    bool public unbackedDebitViolation;

    bytes32 constant EV = keccak256("ev");

    constructor() {
        for (uint256 i; i < 5; ++i) actors.push(address(uint160(0x1000 + i)));
        t = new EnforcedToken(address(this), actors); // every actor may receive a seizure
        for (uint256 i; i < 5; ++i) {
            t.mint(actors[i], 1_000_000);
            ghostMinted += 1_000_000;
        }
    }

    function _actor(uint256 s) internal view returns (address) {
        return actors[s % actors.length];
    }

    function _logged(uint8 action, bytes32 paramsHash) internal {
        ghostHead = keccak256(abi.encode(ghostHead, ghostActions, action, paramsHash, EV));
        ghostActions++;
    }

    // ---------------------------------------------------- user actions
    function transfer(uint256 fs, uint256 ts, uint256 amt) external {
        address from = _actor(fs);
        address to = _actor(ts);
        amt = bound(amt, 0, 2_000_000);
        uint8 st = t.statusOf(from);
        uint256 before = t.balanceOf(from);
        vm.prank(from);
        try t.transfer(to, amt) {
            if (st != 0 && t.balanceOf(from) < before) frozenOutflowViolation = true;
        } catch {}
    }

    function transferFrom(uint256 os, uint256 ss, uint256 ts, uint256 amt) external {
        address owner = _actor(os);
        address spender = _actor(ss);
        address to = _actor(ts);
        amt = bound(amt, 0, 2_000_000);
        vm.prank(owner);
        t.approve(spender, amt);
        uint8 st = t.statusOf(owner);
        uint256 before = t.balanceOf(owner);
        vm.prank(spender);
        try t.transferFrom(owner, to, amt) {
            if (st != 0 && t.balanceOf(owner) < before && owner != to) frozenOutflowViolation = true;
        } catch {}
    }

    // ---------------------------------------------------- compliance actions
    function setStatus(uint256 as_, uint8 s) external {
        address a = _actor(as_);
        s = uint8(bound(s, 0, 2));
        t.setStatus(a, s, EV);
        _logged(1, keccak256(abi.encode(a, s)));
    }

    function placeHold(uint256 as_, uint96 amt, uint256 salt) external {
        address a = _actor(as_);
        bytes32 id = keccak256(abi.encode(salt));
        if (everCreated[id]) return;
        uint256 spendable = t.spendableOf(a);
        if (spendable == 0) return;
        amt = uint96(bound(amt, 1, spendable));
        t.placeHold(id, a, amt, EV);
        everCreated[id] = true;
        holdIds.push(id);
        ghostHeld[a] += amt;
        _logged(2, keccak256(abi.encode(id, a, amt)));
    }

    function releaseHold(uint256 i) external {
        if (holdIds.length == 0) return;
        bytes32 id = holdIds[i % holdIds.length];
        (address a, uint96 amt) = t.holds(id);
        if (a == address(0)) return;
        t.releaseHold(id, EV);
        ghostHeld[a] -= amt;
        _logged(3, keccak256(abi.encode(id)));
    }

    function seize(uint256 i, uint96 amt, uint256 ds) external {
        if (holdIds.length == 0) return;
        bytes32 id = holdIds[i % holdIds.length];
        (address a, uint96 h) = t.holds(id);
        if (a == address(0)) return;
        amt = uint96(bound(amt, 1, h));
        address dest = _actor(ds);
        if (t.statusOf(dest) == 2) return;
        uint256 heldBefore = t.heldOf(a);
        t.seize(id, amt, dest, EV);
        if (heldBefore - t.heldOf(a) != amt) unbackedDebitViolation = true;
        ghostHeld[a] -= amt;
        _logged(4, keccak256(abi.encode(id, amt, dest)));
    }

    function burn(uint256 i, uint96 amt) external {
        if (holdIds.length == 0) return;
        bytes32 id = holdIds[i % holdIds.length];
        (address a, uint96 h) = t.holds(id);
        if (a == address(0)) return;
        amt = uint96(bound(amt, 1, h));
        uint256 heldBefore = t.heldOf(a);
        t.burnFromHold(id, amt, EV);
        if (heldBefore - t.heldOf(a) != amt) unbackedDebitViolation = true;
        ghostHeld[a] -= amt;
        ghostBurned += amt;
        _logged(5, keccak256(abi.encode(id, amt)));
    }

    function actorsLength() external view returns (uint256) {
        return actors.length;
    }
}

contract Invariants is Test {
    Handler h;
    EnforcedToken t;

    function setUp() public {
        h = new Handler();
        t = h.t();
        targetContract(address(h));
    }

    /// Inv. 1 (hold precedence): seize/burn only ever debit value that was held.
    function invariant_holdPrecedence() public view {
        assertFalse(h.unbackedDebitViolation());
    }

    /// Inv. 2 (spendable safety) + hold bookkeeping: held(a) <= balance(a) and equals the sum of active holds.
    function invariant_heldWithinBalance() public view {
        for (uint256 i; i < h.actorsLength(); ++i) {
            address a = h.actors(i);
            assertLe(t.heldOf(a), t.balanceOf(a));
            assertEq(t.heldOf(a), h.ghostHeld(a));
        }
    }

    /// Inv. 3 (freeze safety): no user-initiated transfer ever reduced a non-ACTIVE balance.
    function invariant_freezeSafety() public view {
        assertFalse(h.frozenOutflowViolation());
    }

    /// Inv. 4 (supply conservation): supply = minted - burned-from-holds = sum of balances.
    function invariant_supplyConservation() public view {
        uint256 sum;
        for (uint256 i; i < h.actorsLength(); ++i) sum += t.balanceOf(h.actors(i));
        assertEq(t.totalSupply(), h.ghostMinted() - h.ghostBurned());
        assertEq(t.totalSupply(), sum);
    }

    /// Inv. 6 (log completeness): one chained entry per compliance mutation.
    function invariant_logCompleteness() public view {
        assertEq(t.logCount(), h.ghostActions());
        assertEq(t.logHead(), h.ghostHead());
    }
}
