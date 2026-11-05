// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {EnforcedToken} from "../src/EnforcedToken.sol";
import {SMTToken} from "../src/SMTToken.sol";
import {ComplianceAuthority} from "../src/ComplianceAuthority.sol";

/// Unit tests for the authorization path (Invariant 5) and the enforcement semantics of Table 1.
contract Security is Test {
    bytes32 constant EV = keccak256("case");
    ComplianceAuthority a;
    EnforcedToken t;
    uint256[] pks;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        address[] memory addrs = new address[](3);
        pks = new uint256[](3);
        for (uint256 i; i < 3; ++i) {
            pks[i] = 0x1000 + i;
            addrs[i] = vm.addr(pks[i]);
        }
        for (uint256 i = 1; i < 3; ++i) {
            for (uint256 j = i; j > 0 && addrs[j] < addrs[j - 1]; --j) {
                (addrs[j], addrs[j - 1]) = (addrs[j - 1], addrs[j]);
                (pks[j], pks[j - 1]) = (pks[j - 1], pks[j]);
            }
        }
        a = new ComplianceAuthority(addrs, 2);
        address[] memory custodians = new address[](1);
        custodians[0] = bob; // the seizure destination used below
        t = new EnforcedToken(address(a), custodians);
        t.mint(alice, 1000);
        t.mint(bob, 10);
    }

    function _sigs(bytes memory data, uint256 n, uint256[] memory keys) internal view returns (bytes memory s) {
        bytes32 d = a.digest(address(t), data, EV, n, block.timestamp + 1);
        for (uint256 i; i < keys.length; ++i) {
            (uint8 v, bytes32 r, bytes32 ss) = vm.sign(keys[i], d);
            s = bytes.concat(s, abi.encodePacked(r, ss, v));
        }
    }

    function _two() internal view returns (uint256[] memory k) {
        k = new uint256[](2);
        k[0] = pks[0];
        k[1] = pks[1];
    }

    // ---------------------------------------------------------- quorum
    function test_quorumAcceptsMofN() public {
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV));
        a.execute(address(t), data, EV, block.timestamp + 1, _sigs(data, 0, _two()));
        assertEq(t.statusOf(alice), 1);
    }

    function test_rejectsBelowThreshold() public {
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV));
        uint256[] memory k = new uint256[](1);
        k[0] = pks[0];
        bytes memory sg = _sigs(data, 0, k);
        vm.expectRevert(ComplianceAuthority.BadSignatureLength.selector);
        a.execute(address(t), data, EV, block.timestamp + 1, sg);
    }

    function test_rejectsDuplicateSigner() public {
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV));
        uint256[] memory k = new uint256[](2);
        k[0] = pks[0];
        k[1] = pks[0];
        bytes memory sg = _sigs(data, 0, k);
        vm.expectRevert(ComplianceAuthority.SignersNotAscending.selector);
        a.execute(address(t), data, EV, block.timestamp + 1, sg);
    }

    function test_rejectsOutsider() public {
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV));
        uint256[] memory k = new uint256[](2);
        k[0] = pks[0];
        k[1] = 0xBAD; // not a signer
        // order outsider correctly to isolate the NotSigner path
        if (vm.addr(k[1]) < vm.addr(k[0])) (k[0], k[1]) = (k[1], k[0]);
        bytes memory sg = _sigs(data, 0, k);
        vm.expectRevert();
        a.execute(address(t), data, EV, block.timestamp + 1, sg);
    }

    function test_rejectsReplay() public {
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV));
        bytes memory s = _sigs(data, 0, _two());
        a.execute(address(t), data, EV, block.timestamp + 1, s);
        vm.expectRevert(); // nonce advanced: recovered addresses no longer match signers
        a.execute(address(t), data, EV, block.timestamp + 1, s);
    }

    function test_rejectsTamperedCalldata() public {
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV));
        bytes memory s = _sigs(data, 0, _two());
        bytes memory other = abi.encodeCall(EnforcedToken.setStatus, (bob, 2, EV));
        vm.expectRevert();
        a.execute(address(t), other, EV, block.timestamp + 1, s);
    }

    function test_directCallsRejected() public {
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        t.setStatus(alice, 2, EV);
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        t.seize(keccak256("x"), 1, bob, EV);
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        t.setCustody(alice, true, EV);
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        t.placeHold(keccak256("x"), alice, 1, EV);
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        t.releaseHold(keccak256("x"), EV);
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        t.burnFromHold(keccak256("x"), 1, EV);
        address[] memory xs = new address[](1);
        xs[0] = alice;
        vm.expectRevert(EnforcedToken.NotAuthority.selector);
        t.blockBatch(xs, EV);
    }

    // ---------------------------------------------------------- semantics (Table 1)
    function _act(bytes memory data) internal {
        a.execute(address(t), data, EV, block.timestamp + 1, _sigs(data, a.nonce(), _two()));
    }

    function test_freezeIsReceiveOnly() public {
        _act(abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        t.transfer(bob, 1);
        vm.prank(bob);
        t.transfer(alice, 1); // inbound still allowed
        assertEq(t.balanceOf(alice), 1001);
    }

    function test_blockStopsInbound() public {
        _act(abi.encodeCall(EnforcedToken.setStatus, (alice, 2, EV)));
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, alice));
        t.transfer(alice, 1);
    }

    function test_blockedSpenderCannotTransferFrom() public {
        vm.prank(alice);
        t.approve(bob, 100);
        _act(abi.encodeCall(EnforcedToken.setStatus, (bob, 2, EV)));
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.Restricted.selector, bob));
        t.transferFrom(alice, address(0xC), 1);
    }

    function test_holdReducesSpendable() public {
        _act(abi.encodeCall(EnforcedToken.placeHold, (keccak256("h"), alice, 900, EV)));
        vm.startPrank(alice);
        vm.expectRevert(EnforcedToken.InsufficientSpendable.selector);
        t.transfer(bob, 101);
        t.transfer(bob, 100);
        vm.stopPrank();
    }

    /// Seizure credits only a designated custody account; the list changes only through the quorum.
    function test_seizeOnlyToCustody() public {
        _act(abi.encodeCall(EnforcedToken.placeHold, (keccak256("h"), alice, 50, EV)));
        bytes memory toAlice = abi.encodeCall(EnforcedToken.seize, (keccak256("h"), 10, alice, EV));
        bytes memory sg = _sigs(toAlice, a.nonce(), _two());
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceAuthority.CallFailed.selector, abi.encodeWithSelector(EnforcedToken.NotCustody.selector, alice)
            )
        );
        a.execute(address(t), toAlice, EV, block.timestamp + 1, sg);

        _act(abi.encodeCall(EnforcedToken.setCustody, (alice, true, EV)));
        assertTrue(t.isCustody(alice));
        _act(toAlice);
        assertEq(t.heldOf(alice), 40);

        _act(abi.encodeCall(EnforcedToken.setCustody, (alice, false, EV)));
        sg = _sigs(toAlice, a.nonce(), _two());
        vm.expectRevert();
        a.execute(address(t), toAlice, EV, block.timestamp + 1, sg);
    }

    function test_custodyNeverZeroAddress() public {
        bytes memory data = abi.encodeCall(EnforcedToken.setCustody, (address(0), true, EV));
        bytes memory sg = _sigs(data, a.nonce(), _two());
        vm.expectRevert();
        a.execute(address(t), data, EV, block.timestamp + 1, sg);
        address[] memory zero = new address[](1);
        vm.expectRevert(abi.encodeWithSelector(EnforcedToken.NotCustody.selector, address(0)));
        new EnforcedToken(address(a), zero);
    }

    function test_seizeRequiresHold() public {
        bytes memory data = abi.encodeCall(EnforcedToken.seize, (keccak256("none"), 1, bob, EV));
        bytes memory sg = _sigs(data, a.nonce(), _two());
        vm.expectRevert(
            abi.encodeWithSelector(
                ComplianceAuthority.CallFailed.selector, abi.encodeWithSelector(EnforcedToken.UnknownHold.selector)
            )
        );
        a.execute(address(t), data, EV, block.timestamp + 1, sg);
    }

    function test_seizeCannotExceedHold() public {
        _act(abi.encodeCall(EnforcedToken.placeHold, (keccak256("h"), alice, 50, EV)));
        bytes memory data = abi.encodeCall(EnforcedToken.seize, (keccak256("h"), 51, bob, EV));
        bytes memory sg = _sigs(data, a.nonce(), _two());
        vm.expectRevert();
        a.execute(address(t), data, EV, block.timestamp + 1, sg);
    }

    function test_logIsHashChained() public {
        bytes32 h0 = t.logHead();
        bytes memory data = abi.encodeCall(EnforcedToken.setStatus, (alice, 1, EV));
        _act(data);
        bytes32 expect = keccak256(abi.encode(h0, uint256(0), uint8(1), keccak256(abi.encode(alice, uint8(1))), EV));
        assertEq(t.logHead(), expect);
        assertEq(t.logCount(), 1);
    }

    // ---------------------------------------------------------- SMT rejects members
    function test_smtRejectsRestrictedSender() public {
        string memory json = vm.readFile("data/smt_1000.json");
        SMTToken s = new SMTToken(address(this));
        s.setRoot(vm.parseJsonBytes32(json, ".root"));
        address member = vm.parseJsonAddress(json, ".member.key");
        s.mint(member, 100);
        SMTToken.Proof memory pm;
        pm.bitmap = vm.parseUint(vm.parseJsonString(json, ".member.bitmap"));
        pm.siblings = vm.parseJsonBytes32Array(json, ".member.siblings");
        SMTToken.Proof memory pt;
        pt.bitmap = vm.parseUint(vm.parseJsonString(json, ".recipient.bitmap"));
        pt.siblings = vm.parseJsonBytes32Array(json, ".recipient.siblings");
        address recipient = 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2;
        vm.prank(member);
        vm.expectRevert(abi.encodeWithSelector(SMTToken.Restricted.selector, member));
        s.transferWithProofs(recipient, 1, pm, pt);
    }

    function test_smtPlainTransferDisabled() public {
        SMTToken s = new SMTToken(address(this));
        s.mint(alice, 1);
        vm.prank(alice);
        vm.expectRevert(SMTToken.ProofRequired.selector);
        s.transfer(bob, 1);
    }
}
