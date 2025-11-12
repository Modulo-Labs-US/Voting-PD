// import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
// import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// /**
//  * @title DelegateVoting
//  * @notice Implements the setup phase of a privacy-preserving delegated voting protocol.
//  * Trusted Authority (TA) generates and signs the Merkle root of eligible voters' token list.
//  * The contract logs all critical parameters and provides on-chain verifiability.
//  */
// contract DelegateVoting {

//     using ECDSA for bytes32;

//     /// @notice List of election identifiers
//     bytes32[] public electionIdentifiers;

//     /// @notice List of delegation identifiers
//     bytes32[] public delegationIdentifiers;

//     /// @notice Merkle root of eligible voters' token list (L_T) can we say balance?
//     bytes32 public RT;

// //ultrahonkVerifier verifier;
//     /// @notice Merkle root of delegates' encrypted voting power list at election start (R_eid)
//     mapping(uint256 => bytes32) public REid;

//      mapping(address => bytes32[4]) public Ld; // slot -> ciphertext (e_x,e_y,v_x,v_y)

//  /// @notice L_did delegation identifier mapping from address to hash of cipher text
//     mapping(address => bytes32) public l_did;

//     /// @notice map from delegate addrs to index in l_d for true index subtract 1 from this
//     mapping(address => uint256) public l_d_index;

//        /// @notice array of cipher texts that represents delegate voting power in the order of cex,cey,cvx,cvy
//     bytes32[4][] l_d;

// mapping(address=>mapping(uint256=>bytes32[4])) l_d

//     /// @notice TA’s signature on RT (σ_TA)
//     bytes public signatureTA;

//     /// @notice Lock map for token usage during elections
//     mapping(address => bool) public lockedTokens;

//     mapping(address => bool) public active;

//     /// @notice Mapping of each voter’s address to their number of voting tokens (t_v)
//         mapping(address => uint256) public votingTokens;

//     /// @notice Public key of the Trusted Authority for signature verification
//     bytes public pkTA;

//     bool initialized;

//     /// @notice Public/secret key pair for encryption (sk is off-chain)
//     struct KeyPair {
//         bytes pk; // Public key
//         bytes sk; // Secret key (optional, not stored on-chain)
//     }

//     /// @notice Encryption key registry per participant
//     mapping(address => KeyPair) public encryptionKeys;

//     /// @notice The delay before voting on a proposal may take place, once proposed, in blocks
//     uint public votingDelay;

//     /// @notice The duration of voting on a proposal, in blocks
//     uint public votingPeriod;

//     /// @notice The number of votes required in order for a voter to become a proposer
//     uint public proposalThreshold;

//     /// @notice Initial proposal id set at become
//     uint public initialProposalId;

//     /// @notice The total number of proposals
//     uint public proposalCount;

//     /// @notice The address of the Compound Protocol Timelock
//     TimelockInterface public timelock;

//     /// @notice The address of the Compound governance token
//     TokenInterface public token;
//     // TokenInterface public comp;

//     /// @notice The official record of all proposals ever proposed
//     mapping (uint => Proposal) public proposals;

//     /// @notice The latest proposal for each proposer
//     mapping (address => uint) public latestProposalIds;

//     /// @notice Possible states that a proposal may be in
//     enum ProposalState {
//         Pending,
//         AwaitingInit,
//         Active,
//         AwaitingDecrypt,
//         Canceled,
//         Defeated,
//         Succeeded,
//         Queued,
//         Expired,
//         Executed
//     }

// // This is lifted from governor bravos contract
//  struct Proposal {
//         /// @notice Unique id for looking up a proposal
//         uint id;

//         /// @notice Creator of the proposal
//         address proposer;

//         /// @notice The timestamp that the proposal will be available for execution, set once the vote succeeds
//         uint eta;

//         /// @notice the ordered list of target addresses for calls to be made
//         address[] targets;

//         /// @notice The ordered list of values (i.e. msg.value) to be passed to the calls to be made
//         uint[] values;

//         /// @notice The ordered list of function signatures to be called
//         string[] signatures;

//         /// @notice The ordered list of calldata to be passed to each call
//         bytes[] calldatas;

//         /// @notice The block at which voting begins: holders must delegate their votes prior to this block
//         uint startBlock;

//         /// @notice The block at which voting ends: votes must be cast prior to this block
//         uint endBlock;

//         /// @notice Current number of votes in favor of this proposal
//         bytes32[4] forVotes;

//         /// @notice Current number of votes in opposition to this proposal
//         bytes32[4] againstVotes;

//         /// @notice Current number of votes for abstaining for this proposal
//         bytes32[4] abstainVotes;

//         /// @notice Flag marking whether the proposal has been canceled
//         bool canceled;

//         /// @notice Flag marking whether the proposal has been executed
//         bool executed;

//         /// @notice Flag marking whether the proposal has been initialized
//         bool initialized;

//         /// @notice Flag marking whether the proposal has been decrypted
//         bool decrypted;

//         /// @notice Flag marking whether the proposal was successful only check this if decrypted is true
//         bool successful;

//         /// @notice Flag marking whether the proposal was added to queue
//         bool queued;

//         /// @notice merkle root for voting snapshot
//         bytes32 snapshot;

//         /// @notice Receipts of ballots for the entire set of voters
//         mapping (address => Receipt) receipts;
//     }

//     /// @notice Ballot receipt record for a voter
//     struct Receipt {
//         /// @notice Whether or not a vote has been cast
//         bool hasVoted;

//         /// @notice Whether or not the voter supports the proposal or abstains
//         uint8 support;

//         /// @notice The number of votes the voter had, which were cast
//         uint96 votes;
//     }

// struct Ciphertext {
//         bytes32 e_x;
//         bytes32 e_y;
//         bytes32 v_x;
//         bytes32 v_y;
//     }
//     enum VoteOption { None, Yes, No, Abstain }

//     /// @notice Mapping of proposal ID to Proposal
//     mapping(uint256 => Proposal) public proposals;

//     /// @notice Mapping of voter to their votes per proposal
//     mapping(address => mapping(uint256 => VoteOption)) public votes;

//  //Events

//     event SetupInitialized(
//         bytes32 indexed RT,
//         bytes signatureTA,
//         bytes pkTA
//     );

//     error Setup_Initialized();
//     error Not_Initialized();
//     error Invalid_Signer();
// /***
//  * @notice Used to initialize the contract during delegator constructor
//      * @param timelock_ The address of the Timelock
//      * @param token_ The address of the  token
//      * @param votingPeriod_ The initial voting period
//      * @param votingDelay_ The initial voting delay
//      * @param proposalThreshold_ The initial proposal threshold
//      */
//     constructor(
//         address timelock_,
//         address token_,
//         uint votingPeriod_,
//         uint votingDelay_,
//         uint proposalThreshold_
//     ) public  {
//         require(
//             address(timelock) == address(0),
//             "GovernorBravo::initialize: can only initialize once"
//         );
//         // require(msg.sender == admin, "GovernorBravo::initialize: admin only");
//         require(
//             timelock_ != address(0),
//             "GovernorBravo::initialize: invalid timelock address"
//         );
//         require(
//             comp_ != address(0),
//             "GovernorBravo::initialize: invalid comp address"
//         );
//         require(
//             votingPeriod_ >= MIN_VOTING_PERIOD &&
//                 votingPeriod_ <= MAX_VOTING_PERIOD,
//             "GovernorBravo::initialize: invalid voting period"
//         );
//         require(
//             votingDelay_ >= MIN_VOTING_DELAY &&
//                 votingDelay_ <= MAX_VOTING_DELAY,
//             "GovernorBravo::initialize: invalid voting delay"
//         );
//         require(
//             proposalThreshold_ >= MIN_PROPOSAL_THRESHOLD &&
//                 proposalThreshold_ <= MAX_PROPOSAL_THRESHOLD,
//             "GovernorBravo::initialize: invalid proposal threshold"
//         );
//         timelock = TimelockInterface(timelock_);
//         token =TokenInterface(token_);
//         votingPeriod = votingPeriod_;
//         votingDelay = votingDelay_;
//         proposalThreshold = proposalThreshold_;
//         initialProposalId++;
//         verifier = new UltraVerifier();
//     }

// // onchain setUp
// function setup(
//     bytes32 _pkTa,
//     bytes32 _sk,
//     bytes32 _root
//     bytes signatureTA_) external{

//         if (initialized) revert Setup_Initialized();
//        // require(!initialized,"already initialized");

//            // verify signature: we assume TA signed the 32-byte RT using eth_sign style
//         // i.e. signer = ECDSA.recover(keccak256("\x19Ethereum Signed Message:\n32", RT), sigma)
//         bytes hash=ECDSA.toEthSignedMessageHash(abi.encodePacked(_root));
//         address recover = hash.recover(signatureTA_);

//         if(recover!=_pkTa) revert Invalid_Signer();

//         pkTASig = _pkTASig;
//         RT = _RT;
//         signatureTA = signatureTA_;

//         // init empty lists (already default empty), ensure lock/active maps cleared by default
//         initialized = true;

//         emit SetupInitialized(_RT, _pkTASig);
//     }

// // we need to ensure that delegate also have the token

// //
// // the cipher text is generated with the public key we might need to verify if it is a correct public key
//     function delegateRegistration(Ciphertext calldata ct, bytes memory proof,bytes32 balance) external{

//       if(!initialized) revert Not_Initialized();

//      //require(initialized,"not initialized");

//         if(token.Lock(msg.sender)) revert TokenLockedCannotRegister;
//        if(active[msg.sender]) revert DelegateCannotBeActive;

//         bytes32[] memory inputs= new bytes32[](8);
//         inputs[0]=pkTASig;
//         inputs[1]= balance;
//         inputs[1]=ct.e_x;
//         inputs[2]=ct.e_y;
//         inputs[3]=ct.v_x;
//         inputs[4]=ct.v_y;
//    verifier.verify(proof, inputs,2);

//     active[msg.sender]=true;
//    // locked[msg.sender]=true;

//    if(l_d_index[msg.sender] == 0){
//             l_d_index[msg.sender] = l_d.length+1;
//         }
//         uint256 sender_index = l_d_index[msg.sender]-1;

//     // if new account push ciphertext
//         if (sender_index == l_d.length){
//             l_d.push([cex,cey,cvx,cvy]);
//         }else{
//             // if old account update old index
//             l_d[sender_index] = [cex,cey,cvx,cvy];
//         }
//   //  Ld[msg.sender]=ct;

// emit delegateRegistered();

// function  delegateUnRegistered(Ciphertext calldata ct_old, Ciphertext calldata ct_new, bytes memory proof, bytes32 balance) external{

// if (!token.Lock(msg.sender)) revert TokenMustBeLockBeforeUnRegistering();
// if(!active[msg.sender]) revert DelegateMustBeActive();

// bytes32[] memory inputs= new bytes32[](9);

//   `     inputs[0] = ct_old.e_x;
//         inputs[1] = ct_old.e_y;
//         inputs[2] = ct_old.v_x;
//         inputs[3] = ct_old.v_y;
//         inputs[4] = balance;
//         inputs[5] = ct_new.e_x;
//         inputs[6] = ct_new.e_y;
//         inputs[7] = ct_new.v_x;
//         inputs[8] = ct_new.v_y;
//         require(verifier.verify(proof, inputs, 6), "Invalid Proof");
//         active[msg.sender] = false;

//   require(token.unlock(msg.sender), "token could not unlock");

//         emit UnregisterDelegate(msg.sender,token.isLocked(msg.sender),active[msg.sender],uint256(balance),sender_index);
//  }
//     };

//     function delegate(Ciphertext calldata ct, bytes memory proof, bytes memory hash) external {

//     }

//     function undelegate() external {}

//      function election_setup (
//         address[] memory targets,
//         uint[] memory values,
//         string[] memory signatures,
//         bytes[] memory calldatas,
//         string memory title,
//         string memory description,
//         bytes32[4] memory ct0,
//         uint voting_delay,
//         uint voting_period
//     ) public returns (uint) {
//         /* make sure governance has been deployed*/
//         require(
//             initialProposalId != 0,
//             "GovernorBravo::propose: Governor Bravo private not active"
//         );

//         uint startBlock = block.number +voting_delay;
//         uint endBlock = startBlock +voting_period;

//         /* Create new proposal */
//         proposalCount++;
//         uint newProposalID = proposalCount;
//         Proposal storage newProposal = proposals[newProposalID];

//         /* make sure eid not in leid */
//         require(
//             newProposal.id == 0,
//             "GovernorBravo::propose: This id has been used"
//         );

//         /* populate proposal */
//         newProposal.id = newProposalID;
//         newProposal.proposer = msg.sender;
//         newProposal.eta = 0;
//         newProposal.targets = targets;
//         newProposal.values = values;
//         newProposal.signatures = signatures;
//         newProposal.calldatas = calldatas;
//         newProposal.startBlock = startBlock;
//         newProposal.endBlock = endBlock;
//         newProposal.forVotes = ct0;
//         newProposal.againstVotes = ct0;
//         newProposal.abstainVotes = ct0;
//         newProposal.canceled = false;
//         newProposal.executed = false;
//         newProposal.initialized = false;
//         newProposal.decrypted = false;
//         newProposal.successful = false;
//         newProposal.queued = false;

//         /* emit proposal info */
//         emit ElectionSetup(
//             newProposal.id,
//             msg.sender,
//             startBlock,
//             endBlock,
//             description,
//             title
//         );
//         return newProposal.id;
//     }

// // function initialize(
// //     bytes32 _pkTa,
// //     bytes32 _sk,
// //     bytes32 _root
// //     bytes signatureTA_
// // ) external onlyOwner{
// // pkTA=_pkTa;
// // sk=_sk;
// // RT=_root;

// // emit SetupInitialized(_root,signatureTA_,_pkTa)
// // }

// function setUp(){

// }

// function registerDelegate(){}
// function unregisterDelegate(){}
// function delegate(){}
// function undelegate(){}
// function electionSetup(){}
// function electionStart(){}
// function vote(){}
// function tally(){}

// }

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Token} from "./tokens/Token.sol";

/**
 * @title DelegateVoting
 * @notice Implements the setup phase of a privacy-preserving delegated voting protocol.
 */
contract DelegateVoting {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    Token public token;
    // ==========================
    // State Variables
    // ==========================
    bytes32[] public electionIdentifiers;
    bytes32[] public delegationIdentifiers;
    bytes32 public RT; // Merkle root of eligible voters
    bytes public signatureTA;
    bytes32 p_x;
    bytes32 p_y;
    bytes32 public pkTA;
    bool public initialized;

    // Delegates
    mapping(address => bytes32[4]) public Ld; // single ciphertext per delegate
    mapping(address => mapping(uint256 => bytes32[4])) public l_d; // multi-slot per delegate
    mapping(address => bytes32) public l_did;
    mapping(address => uint256) public l_d_index;
    bytes32[4][] public l_d_array; // array storage fallback
    mapping(address => bool) public active;

    mapping(address => bool) public lockedTokens;
    mapping(address => uint256) public votingTokens;

    // Governance
    uint256 public votingDelay;
    uint256 public votingPeriod;
    uint256 public proposalThreshold;
    uint256 public initialProposalId;
    uint256 public proposalCount;

    // Proposal management
    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public latestProposalIds;

    // Token / Timelock interfaces
    //TimelockInterface public timelock;
    //TokenInterface public token;

    // ==========================
    // Structs
    // ==========================
    // struct KeyPair {
    //     bytes pk;
    //     bytes sk; // secret key stored off-chain
    // }
    // mapping(address => KeyPair) public encryptionKeys;
    //This cannot be stored onchain

    struct Ciphertext {
        bytes32 e_x;
        bytes32 e_y;
        bytes32 v_x;
        bytes32 v_y;
    }

    enum VoteOption {
        None,
        Yes,
        No,
        Abstain
    }

    struct Receipt {
        bool hasVoted;
        uint8 support;
        uint96 votes;
    }

    struct Proposal {
        uint256 id;
        address proposer;
        uint256 eta;
        address[] targets;
        uint256[] values;
        string[] signatures;
        bytes[] calldatas;
        uint256 startBlock;
        uint256 endBlock;
        bytes32[4] forVotes;
        bytes32[4] againstVotes;
        bytes32[4] abstainVotes;
        bool canceled;
        bool executed;
        bool initialized;
        bool decrypted;
        bool successful;
        bool queued;
        bytes32 snapshot;
        mapping(address => Receipt) receipts;
    }

    // ==========================
    // Events
    // ==========================
    event SetupInitialized(bytes32 indexed RT, bytes signatureTA, bytes32 p_x, bytes32 p_y);
    event DelegateRegistered(address indexed delegate);
    event UnregisterDelegate(address indexed delegate, bool locked, bool active, uint256 balance, uint256 index);
    event ElectionSetup(
        uint256 indexed proposalId,
        address proposer,
        uint256 startBlock,
        uint256 endBlock,
        string description,
        string title
    );

    // ==========================
    // Errors
    // ==========================
    error Setup_Initialized();
    error Not_Initialized();
    error Invalid_Signer();
    error TokenLockedCannotRegister();
    error DelegateCannotBeActive();
    error TokenMustBeLockBeforeUnRegistering();
    error DelegateMustBeActive();

    // ==========================
    // Constructor
    // ==========================
    constructor(
        address timelock_,
        address token_,
        uint256 votingPeriod_,
        uint256 votingDelay_,
        uint256 proposalThreshold_
    ) {
        require(timelock_ != address(0), "Invalid timelock address");
        require(token_ != address(0), "Invalid token address");

        // timelock = TimelockInterface(timelock_);
        //token = TokenInt(token_);
        token = Token(token);
        votingPeriod = votingPeriod_;
        votingDelay = votingDelay_;
        proposalThreshold = proposalThreshold_;
        initialProposalId = 1;
    }

    // ==========================
    // Setup Functions
    // ==========================
    // function setup(bytes32 _pkTA, bytes32 p_x_, bytes32 p_y_, bytes32 _root, bytes memory signatureTA_) external {
    //     if (initialized) revert Setup_Initialized();

    //     // Verify signature

    //     bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(_root);
    //   //  bytes32 hash = ECDSA.toEthSignedMessageHash(_root);
    //     address recover = ethHash.recover(ethHash, signatureTA_);
    //     if (recover != address(uint160(uint256(_pkTA)))) revert Invalid_Signer();

    //     pkTA = _pkTA;
    //     p_x = p_x_;
    //     p_y = p_y_;
    //     RT = _root;
    //     signatureTA = signatureTA_;
    //     initialized = true;

    //     emit SetupInitialized(_root, signatureTA_, p_x_, p_y_);
    // }

    function setup(bytes32 _pkTA, bytes32 p_x_, bytes32 p_y_, bytes32 _root, bytes memory signatureTA_) external {
        if (initialized) revert Setup_Initialized();

        // Compute Ethereum-signed message hash
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(_root);

        // Correct: recover signer from signature
        address signer = ECDSA.recover(ethHash, signatureTA_);

        // Compare to the TA’s public key-derived address
        if (signer != address(uint160(uint256(_pkTA)))) revert Invalid_Signer();

        pkTA = _pkTA;
        p_x = p_x_;
        p_y = p_y_;
        RT = _root;
        signatureTA = signatureTA_;
        initialized = true;

        emit SetupInitialized(_root, signatureTA_, p_x_, p_y_);
    }

    // ==========================
    // Delegate Registration
    // ==========================
    function delegateRegistration(Ciphertext calldata ct, bytes memory proof, bytes32 balance) external {
        if (!initialized) revert Not_Initialized();
        if (token.isLocked(msg.sender)) revert TokenLockedCannotRegister();
        if (active[msg.sender]) revert DelegateCannotBeActive();

        bytes32[] memory inputs = new bytes32[](7);
        inputs[0] = p_x;
        inputs[1] = p_y;
        inputs[1] = balance;
        inputs[2] = ct.e_x;
        inputs[3] = ct.e_y;
        inputs[4] = ct.v_x;
        inputs[5] = ct.v_y;

        // we need to verify the ct if they are part of proof or sth
        //  verifier.verify(proof, inputs, 3);

        active[msg.sender] = true;

        if (l_d_index[msg.sender] == 0) {
            l_d_index[msg.sender] = l_d_array.length + 1;
        }
        uint256 sender_index = l_d_index[msg.sender] - 1;

        if (sender_index == l_d_array.length) {
            l_d[msg.sender][sender_index] = [ct.e_x, ct.e_y, ct.v_x, ct.v_y];
        } else {
            l_d[msg.sender][sender_index] = [ct.e_x, ct.e_y, ct.v_x, ct.v_y];
        }

        emit DelegateRegistered(msg.sender);
    }

    // ==========================
    // Delegate Unregistration
    // ==========================
    function delegateUnRegistered(
        Ciphertext calldata ct_old,
        Ciphertext calldata ct_new,
        bytes memory proof,
        bytes32 balance
    ) external {
        if (!active[msg.sender]) revert DelegateMustBeActive();
        if (!token.isLocked(msg.sender)) revert TokenMustBeLockBeforeUnRegistering();

        bytes32[] memory inputs = new bytes32[](9);
        inputs[0] = ct_old.e_x;
        inputs[1] = ct_old.e_y;
        inputs[2] = ct_old.v_x;
        inputs[3] = ct_old.v_y;
        inputs[4] = balance;
        inputs[5] = ct_new.e_x;
        inputs[6] = ct_new.e_y;
        inputs[7] = ct_new.v_x;
        inputs[8] = ct_new.v_y;

        // we need to verify the ciphertext if they are part of proof or sth
        //  require(verifier.verify(proof, inputs, 6), "Invalid Proof");

        active[msg.sender] = false;
        // require(!Token._locked[msg.sender], "token could not unlock");

        uint256 sender_index = l_d_index[msg.sender] - 1;
        l_d_array[sender_index] = [ct_new.e_x, ct_new.e_y, ct_new.v_x, ct_new.v_y];

        emit UnregisterDelegate(
            msg.sender, token.isLocked(msg.sender), active[msg.sender], uint256(balance), sender_index
        );
    }

    // ==========================
    // Election Setup
    // ==========================
    function election_setup(
        address[] memory targets,
        uint256[] memory values,
        string[] memory signatures,
        bytes[] memory calldatas,
        string memory title,
        string memory description,
        bytes32[4] memory ct0,
        uint256 voting_delay,
        uint256 voting_period
    ) public returns (uint256) {
        require(initialProposalId != 0, "GovernorBravo private not active");

        uint256 startBlock = block.number + voting_delay;
        uint256 endBlock = startBlock + voting_period;

        proposalCount++;
        uint256 newProposalID = proposalCount;
        Proposal storage newProposal = proposals[newProposalID];

        require(newProposal.id == 0, "This id has been used");

        newProposal.id = newProposalID;
        newProposal.proposer = msg.sender;
        newProposal.eta = 0;
        newProposal.targets = targets;
        newProposal.values = values;
        newProposal.signatures = signatures;
        newProposal.calldatas = calldatas;
        newProposal.startBlock = startBlock;
        newProposal.endBlock = endBlock;
        newProposal.forVotes = ct0;
        newProposal.againstVotes = ct0;
        newProposal.abstainVotes = ct0;
        newProposal.canceled = false;
        newProposal.executed = false;
        newProposal.initialized = false;
        newProposal.decrypted = false;
        newProposal.successful = false;
        newProposal.queued = false;

        emit ElectionSetup(newProposal.id, msg.sender, startBlock, endBlock, description, title);
        return newProposal.id;
    }
}
