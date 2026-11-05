// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";
import {BridgedEnforcedToken} from "../src/BridgedEnforcedToken.sol";
import {TieredAuthority} from "../src/TieredAuthority.sol";
import {XChainAdapter, IXERC20} from "../src/XChainAdapter.sol";

/// Two-chain tests for issuer-controlled bridging and per-chain propagation (paper, Sections 4.1, 5.6).
///
/// Chains X (id 1) and Y (id 10) are simulated in one EVM by switching `block.chainid`. Each chain has
/// its own TieredAuthority with the SAME signer and guardian set, its own BridgedEnforcedToken, and an
/// allow-listed XChainAdapter. Signers sign one action per chain; the relayer moves bridge messages.
contract Bridge is Test {
    uint256 constant X = 1;
    uint256 constant Y = 10;
    bytes32 constant EV = keccak256("case-2026-031");
    uint32 constant DELAY = 2 days;
    uint256 constant LIMIT = 1_000_000e6; // per bridge, per direction, per day

    struct Net {
        uint256 id;
        TieredAuthority a;
        BridgedEnforcedToken t;
        XChainAdapter bridge;
    }

    Net cx;
    Net cy;
    uint256[5] spk;
    uint256[3] gpk;
    address relayer = address(0xBEEF);
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    // ------------------------------------------------------------------ setup
    function _policy() internal pure returns (TieredAuthority.Policy memory) {
        return TieredAuthority.Policy({
            mR: 2, mI: 3, rolesR: 1, rolesI: 2, gThreshold: 2, delay: DELAY, epoch: 1 days, restrictBudget: 50,
            valueBudget: type(uint96).max
        });
    }

    function _deploy(uint256 chainId) internal returns (Net memory c) {
        vm.chainId(chainId);
        address[] memory s = new address[](5);
        uint8[] memory roles = new uint8[](5);
        bytes32[] memory att = new bytes32[](5);
        for (uint256 i; i < 5; ++i) {
            s[i] = vm.addr(spk[i]);
            roles[i] = i < 3 ? 0 : uint8(i - 2);
        }
        address[] memory g = new address[](3);
        for (uint256 i; i < 3; ++i) g[i] = vm.addr(gpk[i]);
        c.id = chainId;
        c.a = new TieredAuthority(s, roles, att, g, _policy());
        c.t = new BridgedEnforcedToken(address(c.a), new address[](0));
        c.a.bindToken(address(c.t));
        c.bridge = new XChainAdapter(IXERC20(address(c.t)), relayer);
    }

    function setUp() public {
        vm.warp(1_800_000_000);
        for (uint256 i; i < 5; ++i) spk[i] = 0x5000 + i;
        for (uint256 i; i < 3; ++i) gpk[i] = 0x6000 + i;
        cx = _deploy(X);
        cy = _deploy(Y);
        // allow-list each chain's adapter: raising a limit is a slow-tier action
        _slow(cx, abi.encodeCall(BridgedEnforcedToken.setLimits, (address(cx.bridge), LIMIT, LIMIT, EV)));
        _slow(cy, abi.encodeCall(BridgedEnforcedToken.setLimits, (address(cy.bridge), LIMIT, LIMIT, EV)));
        vm.warp(block.timestamp + 1 days); // limits fully available
        _on(cx);
        cx.t.mint(alice, 5_000_000e6);
        vm.prank(alice);
        cx.t.approve(address(cx.bridge), type(uint256).max);
        _on(cy);
        vm.prank(alice);
        cy.t.approve(address(cy.bridge), type(uint256).max);
    }

    // ------------------------------------------------------------------ helpers
    function _on(Net memory c) internal {
        vm.chainId(c.id);
    }

    function _sign(bytes32 d, uint256[] memory pks) internal pure returns (bytes memory sigs) {
        address[] memory ad = new address[](pks.length);
        for (uint256 i; i < pks.length; ++i) ad[i] = vm.addr(pks[i]);
        for (uint256 i = 1; i < pks.length; ++i) {
            for (uint256 j = i; j > 0 && ad[j] < ad[j - 1]; --j) {
                (ad[j], ad[j - 1]) = (ad[j - 1], ad[j]);
                (pks[j], pks[j - 1]) = (pks[j - 1], pks[j]);
            }
        }
        for (uint256 i; i < pks.length; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], d);
            sigs = bytes.concat(sigs, abi.encodePacked(r, s, v));
        }
    }

    function _fastKeys() internal view returns (uint256[] memory k) {
        k = new uint256[](2);
        (k[0], k[1]) = (spk[0], spk[3]);
    }

    function _slowKeys() internal view returns (uint256[] memory k) {
        k = new uint256[](3);
        (k[0], k[1], k[2]) = (spk[0], spk[1], spk[3]);
    }

    /// Signatures for a fast-tier action on chain c (deadline 1 hour).
    function _fastSigs(Net memory c, bytes memory data) internal returns (bytes memory sigs, uint256 dl) {
        _on(c);
        dl = block.timestamp + 1 hours;
        sigs = _sign(c.a.digest(address(c.t), data, EV, c.a.nonce(), dl), _fastKeys());
    }

    function _fast(Net memory c, bytes memory data) internal {
        (bytes memory sigs, uint256 dl) = _fastSigs(c, data);
        c.a.execute(address(c.t), data, EV, dl, sigs);
    }

    function _slow(Net memory c, bytes memory data) internal {
        _on(c);
        uint256 n = c.a.nonce();
        uint256 dl = block.timestamp + 1 hours;
        c.a.queue(address(c.t), data, EV, dl, _sign(c.a.digest(address(c.t), data, EV, n, dl), _slowKeys()));
        vm.warp(block.timestamp + DELAY);
        c.a.executeQueued(address(c.t), data, EV, n, dl);
    }

    function _status(address who, uint8 s) internal pure returns (bytes memory) {
        return abi.encodeCall(EnforcedToken.setStatus, (who, s, EV));
    }

    /// alice bridges `amt` from `src` to `dst`; the relayer delivers it.
    function _bridge(Net memory src, Net memory dst, address to, uint256 amt) internal {
        _on(src);
        vm.prank(alice);
        src.bridge.send(to, amt, dst.id);
        _on(dst);
        vm.prank(relayer);
        dst.bridge.deliver(to, amt);
    }

    // ================================================================== burn-and-mint round trip
    function test_roundTripConservesSupplyAcrossChains() public {
        _on(cx);
        uint256 total = cx.t.totalSupply();
        _bridge(cx, cy, alice, 300e6);
        _on(cx);
        assertEq(cx.t.balanceOf(alice), 5_000_000e6 - 300e6);
        _on(cy);
        assertEq(cy.t.balanceOf(alice), 300e6);
        assertEq(cx.t.totalSupply() + cy.t.totalSupply(), total); // nothing is locked or wrapped
        _bridge(cy, cx, alice, 100e6);
        assertEq(cx.t.totalSupply() + cy.t.totalSupply(), total);
    }

    // ================================================================== bridge-side compliance checks
    function test_frozenOrBlockedHolderCannotBridgeOut() public {
        _fast(cx, _status(alice, 1));
        _on(cx);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        cx.bridge.send(alice, 1e6, Y);
        _fast(cx, _status(alice, 2));
        _on(cx);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        cx.bridge.send(alice, 1e6, Y);
    }

    function test_heldValueCannotBridgeOut() public {
        _fast(cx, abi.encodeCall(EnforcedToken.placeHold, (keccak256("order"), alice, 4_500_000e6, EV)));
        _on(cx);
        vm.prank(alice);
        vm.expectRevert(EnforcedToken.InsufficientSpendable.selector);
        cx.bridge.send(alice, 500_001e6, Y); // spendable is 500,000
        vm.prank(alice);
        cx.bridge.send(alice, 500_000e6, Y);
        assertEq(cx.t.heldOf(alice), 4_500_000e6); // the held value stayed on chain X
    }

    function test_bridgeInRespectsRecipientStatus() public {
        _fast(cy, _status(bob, 2)); // bob blocked on Y
        _on(cx);
        vm.prank(alice);
        cx.bridge.send(bob, 1e6, Y);
        _on(cy);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, bob));
        cy.bridge.deliver(bob, 1e6);

        _fast(cy, _status(alice, 1)); // FROZEN is receive-only, as for transfers
        _bridge(cx, cy, alice, 1e6);
        assertEq(cy.t.balanceOf(alice), 1e6);
    }

    function test_burnNeedsAllowance() public {
        _on(cx);
        cx.t.mint(bob, 10e6);
        vm.prank(bob);
        vm.expectRevert(); // bob has not approved the adapter
        cx.bridge.send(bob, 1e6, Y);
    }

    function test_onlyAllowListedBridges() public {
        _on(cx);
        vm.prank(bob);
        vm.expectRevert(EnforcedToken.NotMinter.selector);
        cx.t.mint(bob, 1);
        vm.prank(bob);
        vm.expectRevert(BridgedEnforcedToken.NotBridge.selector);
        cx.t.burn(alice, 1);
    }

    function test_setLimitsOnlyByAuthority() public {
        _on(cx);
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        cx.t.setLimits(bob, 1, 1, EV);
    }

    // ================================================================== ERC-7281 rate limits
    function test_rateLimitsRefillLinearly() public {
        _on(cx);
        vm.prank(alice);
        cx.bridge.send(alice, LIMIT, Y); // uses the whole burning limit
        vm.prank(alice);
        vm.expectRevert(BridgedEnforcedToken.LimitExceeded.selector);
        cx.bridge.send(alice, 1, Y);
        vm.warp(block.timestamp + 12 hours);
        assertApproxEqAbs(cx.t.burningCurrentLimitOf(address(cx.bridge)), LIMIT / 2, 1e6);
        vm.warp(block.timestamp + 12 hours);
        assertEq(cx.t.burningCurrentLimitOf(address(cx.bridge)), LIMIT);

        _on(cy);
        vm.prank(relayer);
        cy.bridge.deliver(alice, LIMIT); // a compromised relayer is bounded by the minting limit
        vm.prank(relayer);
        vm.expectRevert(BridgedEnforcedToken.LimitExceeded.selector);
        cy.bridge.deliver(alice, 1);
    }

    function test_compromisedBridgeShutFastReopenedSlow() public {
        bytes memory shut = abi.encodeCall(BridgedEnforcedToken.setLimits, (address(cy.bridge), 0, 0, EV));
        _fast(cy, shut); // restrictive: no delay
        _on(cy);
        assertEq(cy.t.mintingMaxLimitOf(address(cy.bridge)), 0);
        vm.prank(relayer);
        vm.expectRevert(EnforcedToken.NotMinter.selector);
        cy.bridge.deliver(alice, 1);

        bytes memory reopen = abi.encodeCall(BridgedEnforcedToken.setLimits, (address(cy.bridge), LIMIT, LIMIT, EV));
        (bytes memory sigs, uint256 dl) = _fastSigs(cy, reopen);
        vm.expectRevert(TieredAuthority.NotRestrictive.selector); // raising a limit is not restrictive
        cy.a.execute(address(cy.t), reopen, EV, dl, sigs);
        _slow(cy, reopen);
        _on(cy);
        assertEq(cy.t.mintingMaxLimitOf(address(cy.bridge)), LIMIT);
    }

    function test_partialLimitCutIsFastToo() public {
        bytes memory cut = abi.encodeCall(BridgedEnforcedToken.setLimits, (address(cx.bridge), LIMIT / 10, LIMIT, EV));
        _fast(cx, cut);
        _on(cx);
        assertEq(cx.t.mintingMaxLimitOf(address(cx.bridge)), LIMIT / 10);
        assertEq(cx.t.mintingCurrentLimitOf(address(cx.bridge)), LIMIT / 10);
        bytes memory mixed = abi.encodeCall(BridgedEnforcedToken.setLimits, (address(cx.bridge), 0, LIMIT + 1, EV));
        (bytes memory sigs, uint256 dl) = _fastSigs(cx, mixed);
        vm.expectRevert(TieredAuthority.NotRestrictive.selector); // raises the burning limit
        cx.a.execute(address(cx.t), mixed, EV, dl, sigs);
    }

    function test_blockedBridgeCannotBurn() public {
        _fast(cx, _status(address(cx.bridge), 2));
        _on(cx);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, address(cx.bridge)));
        cx.bridge.send(alice, 1e6, Y);
    }

    /// Blocking a bridge shuts it in both directions: it can neither burn nor mint.
    function test_blockedBridgeCannotMint() public {
        _fast(cy, _status(address(cy.bridge), 2));
        _on(cy);
        uint256 supply = cy.t.totalSupply();
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, address(cy.bridge)));
        cy.bridge.deliver(bob, 1e6);
        assertEq(cy.t.totalSupply(), supply);
    }

    // ================================================================== per-chain propagation (Section 5.6)
    function test_restrictionDoesNotSyncAutomatically() public {
        _bridge(cx, cy, alice, 1_000e6);
        _fast(cx, _status(alice, 2)); // blocked on X only
        _on(cy);
        assertEq(cy.t.statusOf(alice), 0); // ERC-7281 alone does not propagate restrictions
        vm.prank(alice);
        cy.t.transfer(bob, 100e6); // funds already on Y still move
        assertEq(cy.t.balanceOf(bob), 100e6);
    }

    function test_samePolicyPropagatesPerChain() public {
        _bridge(cx, cy, alice, 1_000e6);
        bytes memory freeze = _status(alice, 2);
        // the same signers sign one action per chain; both can be collected in parallel
        (bytes memory sx, uint256 dlx) = _fastSigs(cx, freeze);
        (bytes memory sy, uint256 dly) = _fastSigs(cy, freeze);
        _on(cx);
        cx.a.execute(address(cx.t), freeze, EV, dlx, sx);
        _on(cy);
        cy.a.execute(address(cy.t), freeze, EV, dly, sy);
        assertEq(cy.t.statusOf(alice), 2);
        _on(cx);
        assertEq(cx.t.statusOf(alice), 2);
        // neither a transfer nor a bridge-out works on either chain
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        cx.bridge.send(alice, 1, Y);
        _on(cy);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        cy.t.transfer(bob, 1);
    }

    function test_signaturesForOneChainRejectedOnTheOther() public {
        bytes memory freeze = _status(alice, 1);
        (bytes memory sx, uint256 dl) = _fastSigs(cx, freeze);
        _on(cy);
        vm.expectRevert(); // different chain id and verifying contract in the EIP-712 domain
        cy.a.execute(address(cy.t), freeze, EV, dl, sx);
        // and X's signatures do not work for Y's token through X's authority either
        _on(cx);
        vm.expectRevert(); // the digest binds the target, so the quorum check fails first
        cx.a.execute(address(cy.t), freeze, EV, dl, sx);
        assertEq(cy.t.statusOf(alice), 0);
    }

    function test_queuedActionNotReplayableAcrossChains() public {
        _on(cx);
        bytes memory unblock = _status(alice, 0);
        uint256 n = cx.a.nonce();
        uint256 dl = block.timestamp + 1 hours;
        bytes memory sigs = _sign(cx.a.digest(address(cx.t), unblock, EV, n, dl), _slowKeys());
        cx.a.queue(address(cx.t), unblock, EV, dl, sigs);
        _on(cy);
        vm.expectRevert();
        cy.a.queue(address(cy.t), unblock, EV, dl, sigs);
    }

    function test_evasionRaceOnBridgeOut() public {
        _bridge(cx, cy, alice, 1_000e6); // part of the funds left before the order arrived
        bytes memory freeze = _status(alice, 1);
        (bytes memory sx, uint256 dlx) = _fastSigs(cx, freeze); // signed for both chains at once
        (bytes memory sy, uint256 dly) = _fastSigs(cy, freeze);
        _on(cx);
        cx.a.execute(address(cx.t), freeze, EV, dlx, sx);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        cx.bridge.send(alice, 1_000e6, Y); // the rest cannot follow
        // what already left is a liability of the issuer on Y, so Y's controls reach it
        _on(cy);
        cy.a.execute(address(cy.t), freeze, EV, dly, sy);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        cy.t.transfer(bob, 1);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        cy.bridge.send(alice, 1, X); // and it cannot hop back or onward
        assertEq(cy.t.balanceOf(alice), 1_000e6);
    }
}
