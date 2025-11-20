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
    event Vote(uint256 indexed proposalId, address indexed voter, uint256 support, string message, bytes32[4] vote);
    event DecryptTally(uint256 indexed proposalID, bytes32 percent, bytes32 percent1, bytes32 percent2);
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

    function setup(bytes32 pkTA_, bytes32 p_x_, bytes32 p_y_, bytes32 _root, bytes memory signatureTA_) external {
        if (initialized) revert Setup_Initialized();

        // Compute Ethereum-signed message hash
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(_root);

        // Correct: recover signer from signature
        address signer = ECDSA.recover(ethHash, signatureTA_);

        // Compare to the TA’s public key-derived address
        if (signer != address(uint160(uint256(pkTA_)))) revert Invalid_Signer();

        pkTA = pkTA_;
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



    function start_election(uint256 proposalID, bytes32 votingRoot,address[] memory delegates, string memory description) external{
 require(
            initialProposalId != 0,
            "GovernorBravo::propose: Governor Bravo private not active"
        );

        for (uint i; i < delegates.length; i++){
            require(active[delegates[i]]==true,"Delegates cannot be inactive");
        }
        require(msg.sender == proposals[proposalID].proposer, "You are not the original proposer of this proposal");
        require(block.number >= proposals[proposalID].startBlock, "Trying to start election too early");
        require(block.number <= proposals[proposalID].endBlock, "Trying to start election too late");
        proposals[proposalID].snapshot = votingRoot;
        proposals[proposalID].initialized = true;

        

    }
    function vote(
    Ciphertext memory ct,
    bytes memory proof,
    string memory message,
    bytes32[12] memory rAdd,
    uint8 support,
    bytes32 root,
    uint256 proposalID
    ) external{

          require(
            initialProposalId != 0,
            "GovernorBravo::propose: Governor Bravo private not active"
        );
        Proposal storage currentProposal = proposals[proposalID];
        require(currentProposal.snapshot != bytes32(0), "There is not a valid snapshot for this election, it may not have been started");
        require(token.isLocked(msg.sender), "Your tokens are not locked");
        require(active[msg.sender], "You are not an active delegate");
        require(!currentProposal.receipts[msg.sender].hasVoted, "You have already voted in this proposal");
        require(support >= 0, "votes value must be 0,1, or 2 the input is negative");
        require(support <= 2, "votes value must be 0,1, or 2 the input is > 2");
        require(block.number >= proposals[proposalID].startBlock, "Trying to vote too early");
        require(block.number <= proposals[proposalID].endBlock, "Trying to vote too late");

        bytes32[] memory inputs= new bytes32[](30);

       uint256 index=0;
        for( uint256 i=0; i <rAdd.length; i++){
            inputs[index]= rAdd[i];
            index++;
        }

        inputs[index] = root;
        index+=1;

        
    //    require(verifier.verify(proof, inputs, 4), "Invalid Proof");

        /* count their vote*/
        currentProposal.receipts[msg.sender].hasVoted = true;
        currentProposal.receipts[msg.sender].support = support;

        /* identify if it succeeded */
        bytes32[4] memory resVote = [rAdd[8],rAdd[9],rAdd[10],rAdd[11]];
        if (support == 0){
            proposals[proposalID].forVotes = resVote;
        } else if (support == 1){
            proposals[proposalID].againstVotes = resVote;
        } else if (support == 2){
            proposals[proposalID].abstainVotes = resVote;
        }

        /* emit log */
        emit Vote(proposalID, msg.sender, support, message, resVote);

        }

            function decrypt_tally(
        uint proposalID,
        bytes32[3] memory percents,
        bytes memory proof
    ) public {
        Proposal storage p  = proposals[proposalID];
        require(block.number >= p.endBlock, "election has not finished");

        /* Verify proof*/
        bytes32[] memory inputs = new bytes32[](17);
        inputs[0] = p_x;
        inputs[1] = p_y;
        inputs[2] = p.forVotes[0];
        inputs[3] = p.forVotes[1];
        inputs[4] = p.forVotes[2];
        inputs[5] = p.forVotes[3];
        inputs[6] = p.againstVotes[0];
        inputs[7] = p.againstVotes[1];
        inputs[8] = p.againstVotes[2];
        inputs[9] = p.againstVotes[3];
        inputs[10] = p.abstainVotes[0];
        inputs[11] = p.abstainVotes[1];
        inputs[12] = p.abstainVotes[2];
        inputs[13] = p.abstainVotes[3];
        inputs[14] = percents[0];
        inputs[15] = percents[1];
        inputs[16] = percents[2];
     //   require(verifier.verify(proof, inputs, 8), "Invalid Proof");

        /* mark proposal as decrypted */
        p.decrypted = true;
        if (percents[0] > percents[1]){
            p.successful = true;
        }else{
            p.successful = false;
        }

        /* emit */
        emit DecryptTally(proposalID, percents[0], percents[1], percents[2]);
    }

    
}
