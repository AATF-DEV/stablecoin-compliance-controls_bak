// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title EnforcedToken
/// @notice Reference enforcement module from the paper (Sections 2.3 and 5).
///   * Account state is packed into ONE storage slot: balance (uint128),
///     aggregate held amount (uint120) and status (uint8). A transfer therefore
///     reads the compliance state of sender and recipient "for free" with the
///     balance slots it must touch anyway (CO-1, CO-2).
///   * Holds are individually identified records (CO-4). SEIZE and BURN can only
///     debit an existing active hold (CO-3, two-phase irreversibility).
///   * Every compliance mutation extends a hash-chained log head (CO-6).
///   * SEIZE can only credit a designated custody account. The custody list is fixed at deployment
///     and changed only by `authority` (each change logged), so an irreversible seizure cannot
///     send value to a mistyped or look-alike address (A5).
///   * Only `authority` (a ComplianceAuthority quorum, CO-8) can mutate compliance state.
contract EnforcedToken {
    // ---------------------------------------------------------------- types
    uint8 public constant ACTIVE = 0;
    uint8 public constant FROZEN = 1; // outbound blocked, inbound allowed (receive-only)
    uint8 public constant BLOCKED = 2; // inbound and outbound blocked

    struct Account {
        uint128 balance;
        uint120 held;
        uint8 status;
    }

    struct Hold {
        address account;
        uint96 amount;
    }

    // ---------------------------------------------------------------- storage
    mapping(address => Account) internal _acct;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(bytes32 => Hold) public holds;
    uint256 public totalSupply;
    bytes32 public logHead;
    uint256 public logCount;
    mapping(address => bool) public isCustody; // designated seizure destinations

    address public immutable authority;
    address public immutable minter;

    // ---------------------------------------------------------------- events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event CustodySet(address indexed account, bool allowed);
    event ComplianceAction(
        uint256 indexed seq, uint8 indexed action, bytes32 paramsHash, bytes32 evidenceHash, bytes32 newHead
    );

    // action tags for the log
    uint8 internal constant A_STATUS = 1;
    uint8 internal constant A_HOLD = 2;
    uint8 internal constant A_RELEASE = 3;
    uint8 internal constant A_SEIZE = 4;
    uint8 internal constant A_BURN = 5;
    uint8 internal constant A_BATCH_BLOCK = 6;
    uint8 internal constant A_CUSTODY = 8; // 7 is A_LIMITS in BridgedEnforcedToken

    // ---------------------------------------------------------------- errors
    error Restricted(address account);
    error InsufficientSpendable();
    error NotAuthority();
    error NotMinter();
    error HoldExists();
    error UnknownHold();
    error HoldExceedsSpendable();
    error ExceedsHold();
    error BadStatus();
    error Overflow();
    error NotCustody(address account);

    modifier onlyAuthority() {
        if (msg.sender != authority) revert NotAuthority();
        _;
    }

    /// @param custodians initial custody accounts: the only addresses `seize` can credit.
    constructor(address authority_, address[] memory custodians) {
        authority = authority_;
        minter = msg.sender;
        for (uint256 i; i < custodians.length; ++i) {
            if (custodians[i] == address(0)) revert NotCustody(address(0));
            isCustody[custodians[i]] = true;
            emit CustodySet(custodians[i], true);
        }
    }

    // ================================================================ ERC-20
    function balanceOf(address a) external view returns (uint256) {
        return _acct[a].balance;
    }

    function heldOf(address a) external view returns (uint256) {
        return _acct[a].held;
    }

    function statusOf(address a) external view returns (uint8) {
        return _acct[a].status;
    }

    function spendableOf(address a) external view returns (uint256) {
        Account memory x = _acct[a];
        return uint256(x.balance) - x.held;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        emit Approval(msg.sender, spender, amt);
        return true;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        // CO-1: a blocked spender (e.g. a sanctioned router) cannot move third-party funds.
        if (_acct[msg.sender].status == BLOCKED) revert Restricted(msg.sender);
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        _transfer(from, to, amt);
        return true;
    }

    function mint(address to, uint256 amt) external virtual {
        if (msg.sender != minter) revert NotMinter();
        Account storage t = _acct[to];
        if (t.status == BLOCKED) revert Restricted(to);
        uint256 nb = uint256(t.balance) + amt;
        if (nb > type(uint128).max) revert Overflow();
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded: nb <= type(uint128).max checked above
        t.balance = uint128(nb);
        totalSupply += amt;
        emit Transfer(address(0), to, amt);
    }

    function _transfer(address from, address to, uint256 amt) internal {
        Account memory f = _acct[from]; // one SLOAD: balance + held + status
        if (f.status != ACTIVE) revert Restricted(from); // FROZEN and BLOCKED both stop outbound
        if (uint256(f.balance) - f.held < amt) revert InsufficientSpendable(); // held <= balance (Inv. 2)

        Account storage t = _acct[to]; // the recipient slot is read anyway to credit it
        if (t.status == BLOCKED) revert Restricted(to);

        unchecked {
            // forge-lint: disable-next-line(unsafe-typecast) -- bounded: amt <= balance - held < 2^128
            _acct[from].balance = f.balance - uint128(amt); // amt <= balance < 2^128
        }
        uint256 nb = uint256(t.balance) + amt;
        if (nb > type(uint128).max) revert Overflow();
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded: nb <= type(uint128).max checked above
        t.balance = uint128(nb);
        emit Transfer(from, to, amt);
    }

    // ================================================================ compliance actions
    function setStatus(address a, uint8 s, bytes32 evidenceHash) external onlyAuthority {
        if (s > BLOCKED) revert BadStatus();
        _acct[a].status = s;
        _log(A_STATUS, keccak256(abi.encode(a, s)), evidenceHash);
    }

    /// @notice Block many addresses in one call (sanctions-list ingestion).
    function blockBatch(address[] calldata accounts, bytes32 evidenceHash) external onlyAuthority {
        for (uint256 i; i < accounts.length; ++i) {
            _acct[accounts[i]].status = BLOCKED;
        }
        _log(A_BATCH_BLOCK, keccak256(abi.encodePacked(accounts)), evidenceHash);
    }

    /// @notice PREVENT TRANSFER: reserve `amt` of `a`'s spendable balance under hold `id`.
    function placeHold(bytes32 id, address a, uint96 amt, bytes32 evidenceHash) external onlyAuthority {
        if (holds[id].account != address(0)) revert HoldExists();
        Account storage x = _acct[a];
        if (uint256(x.held) + amt > x.balance) revert HoldExceedsSpendable();
        x.held += uint120(amt);
        holds[id] = Hold(a, amt);
        _log(A_HOLD, keccak256(abi.encode(id, a, amt)), evidenceHash);
    }

    /// @notice RELEASE: reverse a hold (remediation path, CO-4).
    function releaseHold(bytes32 id, bytes32 evidenceHash) external onlyAuthority {
        Hold memory h = holds[id];
        if (h.account == address(0)) revert UnknownHold();
        _acct[h.account].held -= uint120(h.amount);
        delete holds[id];
        _log(A_RELEASE, keccak256(abi.encode(id)), evidenceHash);
    }

    /// @notice SEIZE: move `amt` out of an existing hold to the custody account `dest`. Irreversible.
    function seize(bytes32 id, uint96 amt, address dest, bytes32 evidenceHash) external onlyAuthority {
        if (!isCustody[dest]) revert NotCustody(dest);
        address a = _debitHold(id, amt);
        Account storage d = _acct[dest];
        if (d.status == BLOCKED) revert Restricted(dest);
        uint256 nb = uint256(d.balance) + amt;
        if (nb > type(uint128).max) revert Overflow();
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded: nb <= type(uint128).max checked above
        d.balance = uint128(nb);
        emit Transfer(a, dest, amt);
        _log(A_SEIZE, keccak256(abi.encode(id, amt, dest)), evidenceHash);
    }

    /// @notice BURN: destroy `amt` out of an existing hold. Irreversible.
    function burnFromHold(bytes32 id, uint96 amt, bytes32 evidenceHash) external onlyAuthority {
        address a = _debitHold(id, amt);
        totalSupply -= amt;
        emit Transfer(a, address(0), amt);
        _log(A_BURN, keccak256(abi.encode(id, amt)), evidenceHash);
    }

    /// @notice Add (`allowed`) or remove a designated custody account. Adding a destination for
    ///         irreversible transfers is permissive (slow tier); removing one is restrictive.
    function setCustody(address a, bool allowed, bytes32 evidenceHash) external onlyAuthority {
        if (a == address(0)) revert NotCustody(address(0));
        isCustody[a] = allowed;
        emit CustodySet(a, allowed);
        _log(A_CUSTODY, keccak256(abi.encode(a, allowed)), evidenceHash);
    }

    function _debitHold(bytes32 id, uint96 amt) internal returns (address a) {
        Hold storage h = holds[id];
        a = h.account;
        if (a == address(0)) revert UnknownHold();
        if (amt > h.amount) revert ExceedsHold();
        unchecked {
            h.amount -= amt;
        }
        if (h.amount == 0) delete holds[id];
        Account storage x = _acct[a];
        x.held -= uint120(amt);
        x.balance -= uint128(amt);
    }

    function _log(uint8 action, bytes32 paramsHash, bytes32 evidenceHash) internal {
        uint256 seq = logCount;
        bytes32 head = keccak256(abi.encode(logHead, seq, action, paramsHash, evidenceHash));
        logHead = head;
        logCount = seq + 1;
        emit ComplianceAction(seq, action, paramsHash, evidenceHash, head);
    }
}
