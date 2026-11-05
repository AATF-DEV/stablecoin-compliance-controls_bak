// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {BaselineToken} from "./BaselineToken.sol";

/// @title SMTToken
/// @notice Restriction set committed as the root of a depth-160 Sparse Merkle Tree keyed by
///         address. Only the 32-byte root is stored on-chain, so list updates are O(1).
///         Every transfer must carry non-membership proofs for sender and recipient.
///
///   Tree convention (zero-hash optimisation): an empty subtree hashes to 0, and
///   H(0,0) = 0; otherwise H(l,r) = keccak256(l || r). A restricted leaf is
///   keccak256(key || 0x01). Proofs are compressed: `bitmap` bit i (i = 0 at the leaf
///   level) says whether the sibling at height i is non-zero; only non-zero siblings
///   are sent, ordered from leaf to root.
///
/// @dev Note the interface change: plain `transfer(to, amt)` is disabled. DEXs and
///      lending protocols cannot supply proofs on a user's behalf, which is the main
///      composability cost of this design.
contract SMTToken is BaselineToken {
    uint256 public constant DEPTH = 160;
    bytes32 public root;
    address public immutable authority;

    struct Proof {
        uint256 bitmap;
        bytes32[] siblings;
    }

    error Restricted(address account);
    error ProofRequired();

    event RootUpdated(bytes32 root);

    constructor(address authority_) {
        authority = authority_;
    }

    function setRoot(bytes32 r) external {
        require(msg.sender == authority, "authority");
        root = r;
        emit RootUpdated(r);
    }

    function transferWithProofs(address to, uint256 amt, Proof calldata pFrom, Proof calldata pTo)
        external
        returns (bool)
    {
        bytes32 r = root;
        if (!_nonMember(msg.sender, pFrom, r)) revert Restricted(msg.sender);
        if (!_nonMember(to, pTo, r)) revert Restricted(to);
        BaselineToken._transfer(msg.sender, to, amt);
        return true;
    }

    function _transfer(address, address, uint256) internal pure override {
        revert ProofRequired();
    }

    /// @notice true iff the leaf at `key` is empty under root `r`.
    function _nonMember(address key, Proof calldata p, bytes32 r) internal pure returns (bool) {
        return computeRoot(key, bytes32(0), p.bitmap, p.siblings) == r;
    }

    function computeRoot(address key, bytes32 leaf, uint256 bitmap, bytes32[] calldata sibs)
        public
        pure
        returns (bytes32 node)
    {
        node = leaf;
        uint256 k = uint256(uint160(key));
        uint256 j;
        uint256 start;
        if (leaf == bytes32(0)) {
            // Non-membership: the node stays 0 until the first non-zero sibling,
            // so skip straight to the lowest set bit of the bitmap.
            if (bitmap == 0) return bytes32(0);
            start = _ctz(bitmap);
        }
        for (uint256 i = start; i < DEPTH; ++i) {
            bytes32 sib;
            if ((bitmap >> i) & 1 == 1) {
                sib = sibs[j];
                unchecked {
                    ++j;
                }
            }
            if (node == bytes32(0) && sib == bytes32(0)) continue;
            // bit (159 - height) of the key picks the branch; at height i we look at bit i
            if ((k >> i) & 1 == 1) {
                node = _h(sib, node);
            } else {
                node = _h(node, sib);
            }
        }
    }

    function _ctz(uint256 x) private pure returns (uint256 n) {
        unchecked {
            if (x & type(uint128).max == 0) { n += 128; x >>= 128; }
            if (x & type(uint64).max == 0) { n += 64; x >>= 64; }
            if (x & type(uint32).max == 0) { n += 32; x >>= 32; }
            if (x & type(uint16).max == 0) { n += 16; x >>= 16; }
            if (x & type(uint8).max == 0) { n += 8; x >>= 8; }
            if (x & 0xf == 0) { n += 4; x >>= 4; }
            if (x & 0x3 == 0) { n += 2; x >>= 2; }
            if (x & 0x1 == 0) { n += 1; }
        }
    }

    function _h(bytes32 a, bytes32 b) private pure returns (bytes32 c) {
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            c := keccak256(0x00, 0x40)
        }
    }
}
