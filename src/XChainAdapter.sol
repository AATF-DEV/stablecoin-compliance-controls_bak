// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IXERC20 {
    function mint(address to, uint256 amt) external;
    function burn(address user, uint256 amt) external;
}

/// @title XChainAdapter
/// @notice Minimal stand-in for an issuer-allow-listed bridge adapter (ERC-7281 style). On the source
///         chain `send` burns the caller's tokens and emits a message; on the destination chain a
///         relayer calls `deliver`, which mints. Message transport and its authentication belong to the
///         bridge, not to the token: the token bounds what any adapter can mint or burn by its limits
///         and applies the compliance checks on both sides. Used in tests and benchmarks only.
contract XChainAdapter {
    IXERC20 public immutable token;
    address public immutable relayer;
    uint256 public sent;

    event Sent(uint256 indexed seq, address indexed from, address indexed to, uint256 amount, uint256 dstChainId);
    event Delivered(address indexed to, uint256 amount);

    error NotRelayer();

    constructor(IXERC20 token_, address relayer_) {
        token = token_;
        relayer = relayer_;
    }

    /// @notice Bridge out. The caller must have approved this adapter on the token.
    function send(address to, uint256 amount, uint256 dstChainId) external returns (uint256 seq) {
        token.burn(msg.sender, amount);
        seq = sent++;
        emit Sent(seq, msg.sender, to, amount, dstChainId);
    }

    /// @notice Bridge in, on behalf of the bridge's message layer.
    function deliver(address to, uint256 amount) external {
        if (msg.sender != relayer) revert NotRelayer();
        token.mint(to, amount);
        emit Delivered(to, amount);
    }
}
