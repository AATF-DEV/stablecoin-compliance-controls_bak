// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Minimal view of the token that the authority needs in order to classify actions.
interface IEnforcedToken {
    function authority() external view returns (address);
    function statusOf(address a) external view returns (uint8);
    function setStatus(address a, uint8 s, bytes32 evidenceHash) external;
    function blockBatch(address[] calldata accounts, bytes32 evidenceHash) external;
    function placeHold(bytes32 id, address a, uint96 amt, bytes32 evidenceHash) external;
    function seize(bytes32 id, uint96 amt, address dest, bytes32 evidenceHash) external;
    function burnFromHold(bytes32 id, uint96 amt, bytes32 evidenceHash) external;
    function setCustody(address a, bool allowed, bytes32 evidenceHash) external;
    // bridged tokens only (BridgedEnforcedToken, ERC-7281 limits)
    function setLimits(address bridge, uint256 mintingLimit, uint256 burningLimit, bytes32 evidenceHash) external;
    function mintingMaxLimitOf(address bridge) external view returns (uint256);
    function burningMaxLimitOf(address bridge) external view returns (uint256);
}

/// @title TieredAuthority
/// @notice Asymmetric compliance authority (paper, Section 5.5).
///
///   * Fast tier (`execute`): RESTRICTIVE and reversible actions on the bound token only, i.e.
///     setStatus that strictly raises an account's restriction (Active < Frozen < Blocked),
///     blockBatch, placeHold, and (for a bridged token) setLimits that raises neither of a
///     bridge's limits, so a compromised bridge can be shut down immediately, and setCustody that
///     removes a custody account. Quorum M_r with at least `rolesR` distinct signer roles,
///     no delay, and a per-epoch budget on the number of accounts restrained.
///   * Slow tier (`queue` -> `executeQueued`): EVERYTHING ELSE, i.e. unfreeze/unblock,
///     release, seize, burn, adding a custody account, any other target, and every change to this
///     contract's own configuration (signer rotation, guardians, thresholds, delay, budgets). Quorum M_i > M_r
///     with at least `rolesI` distinct roles; executable only in [eta, eta + GRACE], where
///     eta = queue time + delay; cancellable before execution by a disjoint guardian quorum.
///     Seized plus burned value is capped per epoch; raising the cap is itself a slow-tier action.
///   * Classification happens at execution time and fails closed: anything the fast tier does
///     not recognise as restrictive is rejected there and must go through the slow tier.
///   * Every signer is registered with a role and the hash of its HSM key attestation, so
///     auditors can re-check enrollment. Events list the approving signers (CO-6).
/// @dev ecrecover cannot tell whether a key lives in an HSM; the attestation hash only makes
///      enrollment auditable. `_recover` is virtual so that the symbolic proofs can abstract it.
contract TieredAuthority {
    // ------------------------------------------------------------------ constants
    bytes32 public constant ACTION_TYPEHASH = keccak256(
        "ComplianceAction(address target,bytes32 dataHash,bytes32 evidenceHash,uint256 nonce,uint256 deadline)"
    );
    bytes32 public constant CANCEL_TYPEHASH = keccak256("CancelAction(bytes32 actionId)");
    uint256 public constant GRACE = 14 days; // a queued action expires if not executed in time
    uint256 public constant MIN_DELAY = 1 hours;
    uint256 public constant MAX_ROLES = 8;

    uint8 internal constant ACTIVE = 0;
    uint8 internal constant BLOCKED = 2;

    // ------------------------------------------------------------------ types
    /// One storage slot.
    struct Policy {
        uint8 mR; // fast-tier quorum
        uint8 mI; // slow-tier quorum, mI > mR
        uint8 rolesR; // distinct roles required in a fast-tier quorum
        uint8 rolesI; // distinct roles required in a slow-tier quorum
        uint8 gThreshold; // guardian quorum for cancellation
        uint32 delay; // slow-tier delay in seconds
        uint32 epoch; // budget epoch length in seconds
        uint32 restrictBudget; // accounts restrained through the fast tier per epoch
        uint96 valueBudget; // value seized + burned per epoch
    }

    /// One storage slot.
    struct Usage {
        uint64 epochIndex;
        uint32 restricted;
        uint96 value;
    }

    struct Signer {
        bool active;
        uint8 role;
        bytes32 attestation; // hash of the HSM attestation checked at enrollment
    }

    // ------------------------------------------------------------------ storage
    uint256 private immutable _cachedChainId;
    bytes32 private immutable _cachedDomainSeparator;
    address public immutable deployer;

    address public token;
    Policy public policy;
    Usage public usage;
    uint256 public nonce;

    mapping(address => Signer) public signers;
    uint256 public signerCount;
    mapping(uint256 => uint256) internal _roleCount; // role -> number of active signers
    uint256 public distinctRoles; // number of roles with at least one active signer

    mapping(address => bool) public isGuardian;
    uint256 public guardianCount;

    mapping(bytes32 => uint256) public eta; // queued action id -> earliest execution time

    // ------------------------------------------------------------------ events
    event TokenBound(address indexed token);
    event Executed(bytes32 indexed id, address indexed target, bytes32 indexed evidenceHash, address[] approvers);
    event Queued(
        bytes32 indexed id, address indexed target, bytes32 indexed evidenceHash, uint256 nonce, uint256 eta, address[] approvers
    );
    event ExecutedQueued(bytes32 indexed id, address indexed target);
    event Cancelled(bytes32 indexed id, address[] guardians);
    event SignerAdded(address indexed signer, uint8 role, bytes32 attestation);
    event SignerRemoved(address indexed signer);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event PolicySet(Policy policy);

    // ------------------------------------------------------------------ errors
    error Expired();
    error BadSignatureLength();
    error SignersNotAscending();
    error NotSigner(address recovered);
    error NotGuardian(address recovered);
    error RolesNotCovered();
    error NotRestrictive();
    error BudgetExceeded();
    error UnknownAction();
    error TooEarly();
    error Stale();
    error OnlySelf();
    error BadPolicy();
    error BadMember(address who);
    error AlreadyBound();
    error NotDeployer();
    error WrongToken();
    error CallFailed(bytes reason);

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    // ------------------------------------------------------------------ setup
    constructor(
        address[] memory signerAddrs,
        uint8[] memory roles,
        bytes32[] memory attestations,
        address[] memory guardians,
        Policy memory p
    ) {
        require(signerAddrs.length == roles.length && roles.length == attestations.length, "length");
        deployer = msg.sender;
        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator();
        for (uint256 i; i < signerAddrs.length; ++i) {
            _addSigner(signerAddrs[i], roles[i], attestations[i]);
        }
        for (uint256 i; i < guardians.length; ++i) {
            _addGuardian(guardians[i]);
        }
        _setPolicy(p);
    }

    /// @notice One-time binding of the token this authority controls (the token's constructor
    ///         needs the authority's address, so the two cannot both be immutable). The token
    ///         must name this contract as its authority, so the fast-tier classification and the
    ///         restriction budget apply to the token this authority actually controls. (The value
    ///         budget does not depend on binding: it counts seizures and burns on any target.)
    function bindToken(address t) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (token != address(0) || t == address(0)) revert AlreadyBound();
        if (IEnforcedToken(t).authority() != address(this)) revert WrongToken();
        token = t;
        emit TokenBound(t);
    }

    // ------------------------------------------------------------------ digests
    /// @notice EIP-712 domain. Recomputed if the chain id changes (e.g. after a fork), so a
    ///         signature for one chain is never valid on another.
    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == _cachedChainId ? _cachedDomainSeparator : _buildDomainSeparator();
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("TieredAuthority"),
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
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
    }

    function cancelDigest(bytes32 id) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(CANCEL_TYPEHASH, id))));
    }

    // ------------------------------------------------------------------ fast tier
    /// @notice Execute a restrictive, reversible action on the bound token immediately.
    function execute(address target, bytes calldata data, bytes32 evidenceHash, uint256 deadline, bytes calldata sigs)
        external
        returns (bytes memory ret)
    {
        if (block.timestamp > deadline) revert Expired();
        Policy memory p = policy;
        uint256 n = nonce;
        bytes32 id = digest(target, data, evidenceHash, n, deadline);
        nonce = n + 1;
        address[] memory who = _quorum(id, sigs, p.mR, p.rolesR);

        uint256 weight = restrictiveWeight(target, data);
        if (weight == 0) revert NotRestrictive();
        _spend(p, weight, 0);

        emit Executed(id, target, evidenceHash, who);
        ret = _call(target, data);
    }

    /// @notice Number of accounts an action restrains if it is a fast-tier action, else 0.
    ///         Fails closed: unknown targets, selectors or malformed data give 0.
    function restrictiveWeight(address target, bytes calldata data) public view returns (uint256) {
        if (target != token || target == address(0) || data.length < 4) return 0;
        bytes4 sel = bytes4(data[:4]);
        if (sel == IEnforcedToken.setStatus.selector) {
            (address a, uint8 s,) = abi.decode(data[4:], (address, uint8, bytes32));
            return (s <= BLOCKED && s > IEnforcedToken(target).statusOf(a)) ? 1 : 0;
        }
        if (sel == IEnforcedToken.blockBatch.selector) {
            // Only the array length is needed: read it in place instead of copying the array
            // (O(1) instead of O(K)). An out-of-range offset reverts the slice: fail closed.
            uint256 off = uint256(bytes32(data[4:36]));
            return uint256(bytes32(data[4 + off:36 + off]));
        }
        if (sel == IEnforcedToken.placeHold.selector) return 1;
        if (sel == IEnforcedToken.setLimits.selector) {
            (address b, uint256 m, uint256 u,) = abi.decode(data[4:], (address, uint256, uint256, bytes32));
            IEnforcedToken tk = IEnforcedToken(target);
            return (m <= tk.mintingMaxLimitOf(b) && u <= tk.burningMaxLimitOf(b)) ? 1 : 0;
        }
        if (sel == IEnforcedToken.setCustody.selector) {
            // removing a seizure destination is restrictive; adding one is not
            (, bool allowed,) = abi.decode(data[4:], (address, bool, bytes32));
            return allowed ? 0 : 1;
        }
        return 0;
    }

    // ------------------------------------------------------------------ slow tier
    /// @notice Queue any action. It becomes executable after the policy delay.
    function queue(address target, bytes calldata data, bytes32 evidenceHash, uint256 deadline, bytes calldata sigs)
        external
        returns (bytes32 id)
    {
        if (block.timestamp > deadline) revert Expired();
        Policy memory p = policy;
        uint256 n = nonce;
        id = digest(target, data, evidenceHash, n, deadline);
        nonce = n + 1;
        address[] memory who = _quorum(id, sigs, p.mI, p.rolesI);
        uint256 when = block.timestamp + p.delay;
        eta[id] = when;
        emit Queued(id, target, evidenceHash, n, when, who);
    }

    /// @notice Execute a queued action once its delay has passed. Anyone may submit it.
    function executeQueued(address target, bytes calldata data, bytes32 evidenceHash, uint256 n, uint256 deadline)
        external
        returns (bytes memory ret)
    {
        bytes32 id = digest(target, data, evidenceHash, n, deadline);
        uint256 when = eta[id];
        if (when == 0) revert UnknownAction();
        if (block.timestamp < when) revert TooEarly();
        if (block.timestamp > when + GRACE) revert Stale();
        delete eta[id];
        _spend(policy, 0, irreversibleValue(target, data));
        emit ExecutedQueued(id, target);
        ret = _call(target, data);
    }

    /// @notice Value an action seizes or burns (counted against the per-epoch value budget).
    /// @dev Counted for EVERY target, not only the bound token: another token that names this
    ///      contract as its authority, or the bound token before `bindToken`, must not escape the
    ///      budget. A `seize`/`burnFromHold` selector on any other contract is counted too, which
    ///      only makes the budget stricter (fail closed).
    function irreversibleValue(address, bytes calldata data) public pure returns (uint256) {
        if (data.length < 4) return 0;
        bytes4 sel = bytes4(data[:4]);
        if (sel == IEnforcedToken.seize.selector) {
            (, uint96 amt,,) = abi.decode(data[4:], (bytes32, uint96, address, bytes32));
            return amt;
        }
        if (sel == IEnforcedToken.burnFromHold.selector) {
            (, uint96 amt,) = abi.decode(data[4:], (bytes32, uint96, bytes32));
            return amt;
        }
        return 0;
    }

    /// @notice A disjoint guardian quorum cancels a queued action before it executes.
    function cancel(bytes32 id, bytes calldata gsigs) external {
        if (eta[id] == 0) revert UnknownAction();
        address[] memory who = _guardianQuorum(cancelDigest(id), gsigs, policy.gThreshold);
        delete eta[id];
        emit Cancelled(id, who);
    }

    // ------------------------------------------------------------------ configuration (slow tier only)
    function addSigner(address s, uint8 role, bytes32 attestation) external onlySelf {
        _addSigner(s, role, attestation);
        _checkPolicy(policy);
    }

    function removeSigner(address s) external onlySelf {
        Signer memory x = signers[s];
        if (!x.active) revert BadMember(s);
        delete signers[s];
        signerCount -= 1;
        if (--_roleCount[x.role] == 0) distinctRoles -= 1;
        emit SignerRemoved(s);
        _checkPolicy(policy);
    }

    function addGuardian(address g) external onlySelf {
        _addGuardian(g);
        _checkPolicy(policy);
    }

    function removeGuardian(address g) external onlySelf {
        if (!isGuardian[g]) revert BadMember(g);
        isGuardian[g] = false;
        guardianCount -= 1;
        emit GuardianRemoved(g);
        _checkPolicy(policy);
    }

    function setPolicy(Policy calldata p) external onlySelf {
        _setPolicy(p);
    }

    // ------------------------------------------------------------------ views
    function roleCount(uint256 role) external view returns (uint256) {
        return _roleCount[role];
    }

    // ------------------------------------------------------------------ internals
    function _addSigner(address s, uint8 role, bytes32 attestation) internal {
        if (s == address(0) || signers[s].active || isGuardian[s] || role >= MAX_ROLES) revert BadMember(s);
        signers[s] = Signer(true, role, attestation);
        signerCount += 1;
        if (_roleCount[role]++ == 0) distinctRoles += 1;
        emit SignerAdded(s, role, attestation);
    }

    function _addGuardian(address g) internal {
        if (g == address(0) || isGuardian[g] || signers[g].active) revert BadMember(g);
        isGuardian[g] = true;
        guardianCount += 1;
        emit GuardianAdded(g);
    }

    function _setPolicy(Policy memory p) internal {
        _checkPolicy(p);
        policy = p;
        emit PolicySet(p);
    }

    /// The policy must stay satisfiable and keep the slow tier strictly stronger.
    function _checkPolicy(Policy memory p) internal view {
        uint256 roles = distinctRoles;
        if (
            p.mR == 0 || p.mI <= p.mR || p.mI > signerCount // quorums: 1 <= mR < mI <= N
                || p.rolesR == 0 || p.rolesR > p.mR || p.rolesI < p.rolesR || p.rolesI > p.mI || p.rolesI > roles
                || p.gThreshold == 0 || p.gThreshold > guardianCount // a cancel quorum must exist
                || p.delay < MIN_DELAY || p.epoch == 0
        ) revert BadPolicy();
    }

    function _spend(Policy memory p, uint256 restricted, uint256 value) internal {
        Usage memory u = usage;
        uint64 e = uint64(block.timestamp / p.epoch);
        if (u.epochIndex != e) {
            u.epochIndex = e;
            u.restricted = 0;
            u.value = 0;
        }
        uint256 r = uint256(u.restricted) + restricted;
        uint256 v = uint256(u.value) + value;
        if (r > p.restrictBudget || v > p.valueBudget) revert BudgetExceeded();
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded by the uint32/uint96 budgets checked above
        u.restricted = uint32(r);
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded by the uint32/uint96 budgets checked above
        u.value = uint96(v);
        usage = u;
    }

    function _quorum(bytes32 d, bytes calldata sigs, uint256 m, uint256 minRoles)
        internal
        view
        returns (address[] memory who)
    {
        if (sigs.length % 65 != 0) revert BadSignatureLength();
        uint256 k = sigs.length / 65;
        if (k < m) revert BadSignatureLength();
        who = new address[](k);
        uint256 roleMask;
        address last;
        for (uint256 i; i < k; ++i) {
            address rec = _recover(d, sigs, i);
            if (rec <= last) revert SignersNotAscending(); // also rejects address(0)
            Signer memory s = signers[rec];
            if (!s.active) revert NotSigner(rec);
            roleMask |= uint256(1) << s.role;
            who[i] = rec;
            last = rec;
        }
        if (_popcount(roleMask) < minRoles) revert RolesNotCovered();
    }

    function _guardianQuorum(bytes32 d, bytes calldata sigs, uint256 m) internal view returns (address[] memory who) {
        if (sigs.length % 65 != 0) revert BadSignatureLength();
        uint256 k = sigs.length / 65;
        if (k < m) revert BadSignatureLength();
        who = new address[](k);
        address last;
        for (uint256 i; i < k; ++i) {
            address rec = _recover(d, sigs, i);
            if (rec <= last) revert SignersNotAscending();
            if (!isGuardian[rec]) revert NotGuardian(rec);
            who[i] = rec;
            last = rec;
        }
    }

    function _recover(bytes32 d, bytes calldata sigs, uint256 i) internal view virtual returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            let off := add(sigs.offset, mul(i, 65))
            r := calldataload(off)
            s := calldataload(add(off, 32))
            v := byte(0, calldataload(add(off, 64)))
        }
        return ecrecover(d, v, r, s);
    }

    function _call(address target, bytes calldata data) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = target.call(data);
        if (!ok) revert CallFailed(ret);
    }

    /// Branch-free popcount of the 8-bit role mask (roles are < MAX_ROLES = 8).
    function _popcount(uint256 x) internal pure returns (uint256) {
        x &= 0xff;
        x = x - ((x >> 1) & 0x55);
        x = (x & 0x33) + ((x >> 2) & 0x33);
        return (x + (x >> 4)) & 0x0f;
    }
}
