// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ComplianceAuthority
/// @notice M-of-N quorum gate for compliance actions (CO-8).
///         Signers authorize an EIP-712 digest binding the target, the exact calldata,
///         an evidence hash (pointer to the lawful order / case file, CO-6), a nonce
///         (replay protection) and a deadline. Signatures must be supplied in strictly
///         ascending signer-address order, which rejects duplicates in O(M).
/// @dev On-chain code can only check signatures. Whether the keys live in HSMs is an
///      operational property that this contract cannot observe.
contract ComplianceAuthority {
    bytes32 public constant ACTION_TYPEHASH = keccak256(
        "ComplianceAction(address target,bytes32 dataHash,bytes32 evidenceHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 public immutable DOMAIN_SEPARATOR;

    uint256 public immutable threshold;
    mapping(address => bool) public isSigner;
    uint256 public nonce;

    event Executed(address indexed target, bytes32 indexed evidenceHash, uint256 nonce, bytes32 dataHash);

    error Expired();
    error BadSignatureLength();
    error SignersNotAscending();
    error NotSigner(address recovered);
    error CallFailed(bytes reason);

    constructor(address[] memory signers, uint256 m) {
        require(m > 0 && m <= signers.length, "bad threshold");
        for (uint256 i; i < signers.length; ++i) {
            require(signers[i] != address(0) && !isSigner[signers[i]], "bad signer");
            isSigner[signers[i]] = true;
        }
        threshold = m;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ComplianceAuthority"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function digest(address target, bytes calldata data, bytes32 evidenceHash, uint256 n, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(ACTION_TYPEHASH, target, keccak256(data), evidenceHash, n, deadline));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @param sigs packed 65-byte (r,s,v) signatures, ordered by ascending signer address.
    function execute(address target, bytes calldata data, bytes32 evidenceHash, uint256 deadline, bytes calldata sigs)
        external
        returns (bytes memory ret)
    {
        if (block.timestamp > deadline) revert Expired();
        uint256 m = threshold;
        if (sigs.length != m * 65) revert BadSignatureLength();

        uint256 n = nonce;
        bytes32 d = digest(target, data, evidenceHash, n, deadline);
        nonce = n + 1;

        address last;
        for (uint256 i; i < m; ++i) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                let off := add(sigs.offset, mul(i, 65))
                r := calldataload(off)
                s := calldataload(add(off, 32))
                v := byte(0, calldataload(add(off, 64)))
            }
            address rec = ecrecover(d, v, r, s);
            if (rec <= last) revert SignersNotAscending(); // also rejects address(0)
            if (!isSigner[rec]) revert NotSigner(rec);
            last = rec;
        }

        emit Executed(target, evidenceHash, n, keccak256(data));
        bool ok;
        (ok, ret) = target.call(data);
        if (!ok) revert CallFailed(ret);
    }
}
