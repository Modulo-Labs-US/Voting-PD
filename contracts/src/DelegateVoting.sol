// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Token} from "./tokens/Token.sol";
import {Groth16Verifier} from "./verifier.sol";

/**
 * @title DelegateVoting
 * @notice Implements the setup phase of a privacy-preserving delegated voting protocol.
 */
contract DelegateVoting {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    Token public token;
    Groth16Verifier public verifier;
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
    mapping(address => bool) private hasIndex;
    uint256 index_length;
    // bytes32[4][] public l_d_array; // array storage fallback
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
    event UnregisterDelegate(address indexed delegate, bool locked, bool active, uint256 index);
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
    event Delegation(
        address indexed delegator,
        bytes32 e_x,
        bytes32 e_y,
        bytes32 v_x,
        bytes32 v_y
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
        token = Token(token_);
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

    function setup(address tA_, bytes32 pkTA_, bytes32 p_x_, bytes32 p_y_, bytes32 _root, bytes memory signatureTA_)
        external
    {
        if (initialized) revert Setup_Initialized();

        // Compute Ethereum-signed message hash
        bytes32 ethHash = MessageHashUtils.toEthSignedMessageHash(_root);

        // Correct: recover signer from signature
        address signer = ECDSA.recover(ethHash, signatureTA_);

        // check if the signer is a correct signer
        if (signer != tA_) revert Invalid_Signer();

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
    function delegateRegistration(
        Ciphertext calldata ct,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes32[6] calldata pubSignals
    ) external {
        if (!initialized) revert Not_Initialized();
        if (token.isLocked(msg.sender)) revert TokenLockedCannotRegister();
        if (active[msg.sender]) revert DelegateCannotBeActive();

        // bytes32[] memory inputs = new bytes32[](6);
        // inputs[0] = p_x;
        // inputs[1] = p_y;
        // // inputs[1] = balance;
        // inputs[2] = ct.e_x;
        // inputs[3] = ct.e_y;
        // inputs[4] = ct.v_x;
        // inputs[5] = ct.v_y;

        uint256[6] memory pub;
        for (uint256 i = 0; i < 6; i++) {
            pub[i] = uint256(pubSignals[i]);
        }

        require(verifier.verifyProof(pA, pB, pC, pub), "invalid proof");
        // we need to check if the ciphertext is correctly generated here
        // we only need to check if the ciphertext is formed correctly here
        // we need to verify the ct if they are part of proof or sth
        //  verifier.verify(proof, inputs, 3);

        active[msg.sender] = true;
        // The design is such that we need to track the index
        if (!hasIndex[msg.sender]) {
            l_d_index[msg.sender] = index_length;

            //    l_d_index[msg.sender] = l_d_array.length + 1;

            // uint256 sender_index = l_d_index[msg.sender] - 1;

            l_d[msg.sender][index_length] = [ct.e_x, ct.e_y, ct.v_x, ct.v_y];

            index_length++;
        } else {
            uint256 idx = l_d_index[msg.sender];
            l_d[msg.sender][idx] = [ct.e_x, ct.e_y, ct.v_x, ct.v_y];
        }
        // if (sender_index == l_d_array.length) {
        //     l_d[msg.sender][sender_index] = [ct.e_x, ct.e_y, ct.v_x, ct.v_y];
        // } else {
        //     l_d[msg.sender][sender_index] = [ct.e_x, ct.e_y, ct.v_x, ct.v_y];
        // }

        emit DelegateRegistered(msg.sender);
    }

    // ==========================
    // Delegate Unregistration
    // ==========================
    function delegateUnRegistered(
        Ciphertext calldata ct_old,
        Ciphertext calldata ct_new,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes32[6] calldata pubSignals
    ) external {
        if (!active[msg.sender]) revert DelegateMustBeActive();
        if (!token.isLocked(msg.sender)) revert TokenMustBeLockBeforeUnRegistering();

        // bytes32[] memory inputs = new bytes32[](9);
        // bytes32[] memory inputs = new bytes32[](6);
        // inputs[0] = p_x;
        // inputs[1] = p_y;
        // inputs[2] = ct_old.e_x;
        // inputs[3] = ct_old.e_y;
        // inputs[4] = ct_old.v_x;
        // inputs[5] = ct_old.v_y;
        // //  inputs[4] = balance;
        // inputs[5] = ct_new.e_x;
        // inputs[6] = ct_new.e_y;
        // inputs[7] = ct_new.v_x;
        // inputs[8] = ct_new.v_y;

        uint256[6] memory pub;
        for (uint256 i = 0; i < 6; i++) {
            pub[i] = uint256(pubSignals[i]);
        }

        require(verifier.verifyProof(pA, pB, pC, pub), "invalid proof");

        // we need to verify the ciphertext if they are part of proof or sth
        //  require(verifier.verify(proof, inputs, 6), "Invalid Proof");
        //    require( verifier.verifyProof(proof, inputs,6), "invalid proof");

        active[msg.sender] = false;
        // require(!Token._locked[msg.sender], "token could not unlock");

        uint256 idx = l_d_index[msg.sender];
        l_d[msg.sender][idx] = [ct_new.e_x, ct_new.e_y, ct_new.v_x, ct_new.v_y];

        emit UnregisterDelegate(msg.sender, token.isLocked(msg.sender), active[msg.sender], sender_index);
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

    function start_election(uint256 proposalID, address[] memory delegates, string memory description) external {
        require(initialProposalId != 0, "GovernorBravo::propose: Governor Bravo private not active");

        for (uint256 i; i < delegates.length; i++) {
            require(active[delegates[i]] == true, "Delegates cannot be inactive");
        }
        require(msg.sender == proposals[proposalID].proposer, "You are not the original proposer of this proposal");
        require(block.number >= proposals[proposalID].startBlock, "Trying to start election too early");
        require(block.number <= proposals[proposalID].endBlock, "Trying to start election too late");
        //   proposals[proposalID].snapshot = votingRoot;
        proposals[proposalID].initialized = true;
    }

    function delegate(
        Ciphertext calldata ct,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        bytes32[6] calldata pubSignals
    ) external {
        if (!initialized) revert Not_Initialized();
        require(token.isLocked(msg.sender), "Your tokens are not locked");

        uint256[6] memory pub;
        for (uint256 i = 0; i < 6; i++) {
            pub[i] = uint256(pubSignals[i]);
        }

        require(delegate_verifier.verifyProof(pA, pB, pC, pub), "Invalid delegation proof");

        active[msg.sender] = true;

        // add in the ciphertext beforehand, verify this was done in zkp
        Ld[msg.sender] = [ct.e_x, ct.e_y, ct.v_x, ct.v_y]; 
        l_did[msg.sender] = keccak256(abi.encodePacked(delegateAddress)); // Unique identifier for the delegation

        emit Delegation(msg.sender, ct.e_x, ct.e_y, ct.v_x, ct.v_y);
    }

    // we are using a merkle tree to include all the ciphertext here

    // ct has four elements
    function vote(
        Ciphertext memory ct,
        bytes32[] memory proof,
        string memory message,
        bytes32[4] memory rAdd, // holds ct for easy addition
        uint8 support,
        bytes32 root, // supposed to be the root of Ld (election powers)
        uint256 proposalID
    ) external {
        require(initialProposalId != 0, "GovernorBravo::propose: Governor Bravo private not active");
        Proposal storage currentProposal = proposals[proposalID];
        require(
            currentProposal.snapshot != bytes32(0),
            "There is not a valid snapshot for this election, it may not have been started"
        );
        require(token.isLocked(msg.sender), "Your tokens are not locked");
        require(active[msg.sender], "You are not an active delegate");
        require(!currentProposal.receipts[msg.sender].hasVoted, "You have already voted in this proposal");
        require(support >= 0, "votes value must be 0,1, or 2 the input is negative");
        require(support <= 2, "votes value must be 0,1, or 2 the input is > 2");
        require(block.number >= proposals[proposalID].startBlock, "Trying to vote too early");
        require(block.number <= proposals[proposalID].endBlock, "Trying to vote too late");

        // bytes32[] memory inputs = new bytes32[](26);

        // uint256 index = 0;
        // for (uint256 i = 0; i < rAdd.length; i++) {
        //     inputs[index] = rAdd[i];
        //     index++;
        // }

        // inputs[index] = root;
        // index += 1;

        //    require(verifier.verify(proof, inputs, 4), "Invalid Proof");

        /* count their vote*/

        bytes32 leaf = keccak256(abi.encode(ct.e_x, ct.e_y, ct.v_x, ct.v_y));
        require(_verifyMerkleProof(leaf, proof, root), "invalid merkle tree");

        /* identify if it succeeded */
        bytes32[4] memory resVote = [rAdd[0], rAdd[1], rAdd[2], rAdd[3]];
        for (uint256 i = 0; i < 4; i++) {
            if (support == 0) {
                currentProposal.forVotes[i] = _add(currentProposal.forVotes[i], resVote[i]);
            } else if (support == 1) {
                currentProposal.againstVotes[i] = _add(currentProposal.againstVotes[i], resVote[i]);
            } else {
                currentProposal.abstainVotes[i] = _add(currentProposal.abstainVotes[i], resVote[i]);
            }
        }

        currentProposal.receipts[msg.sender].hasVoted = true;
        currentProposal.receipts[msg.sender].support = support;

        emit Vote(proposalID, msg.sender, support, message, resVote);
    }

    function _verifyMerkleProof(bytes32 leaf, bytes32[] memory proof, bytes32 root) internal pure returns (bool) {
        bytes32 hash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 el = proof[i];

            if (hash < el) {
                hash = keccak256(abi.encodePacked(hash, el));
            } else {
                hash = keccak256(abi.encodePacked(el, hash));
            }
        }
        return hash == root;
    }

    function _add(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return bytes32(uint256(a) + uint256(b));
    }

    // only the TA shoud be able to call it like we need to verify that it is the Ta that actually calls it
    function decrypt_tally(
        uint256 proposalID,
        bytes32[4] memory forVotes,
        bytes32[4] memory againstVotes,
        bytes32[4] memory abstainVotes
    ) public {
        Proposal storage p = proposals[proposalID];
        require(block.number >= p.endBlock, "election has not finished");

        // mapping each votes to the result
        for (uint256 i = 0; i < 4; i++) {
            forVotes[i] = p.forVotes[i];
            againstVotes[i] = p.againstVotes[i];
            abstainVotes[i] = p.abstainVotes[i];
        } /* mark proposal as decrypt*/
        p.decrypted = true;

        // we are working in prime field
        uint256 countFor;
        uint256 countAgainst;
        for (uint256 i = 0; i < 4; i++) {
            if (forVotes[i] > againstVotes[i]) {
                countFor++;
            } else {
                countAgainst++;
            }
        }

        if (countFor > countAgainst) {
            p.successful = true;
        } else {
            p.successful = false;
        }
        // if (percents[0] > percents[1]) {
        //     p.successful = true;
        // } else {
        //     p.successful = false;
        // }

        /* emit */
        // emit DecryptTally(proposalID, percents[0], percents[1], percents[2]);
    }
}
