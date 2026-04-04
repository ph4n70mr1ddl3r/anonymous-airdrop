// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IRiscZeroVerifier} from "@risc0/IRiscZeroVerifier.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

error ZeroVerifierAddress();
error ZeroImageId();
error ZeroTokenAddress();
error ZeroMerkleRoot();
error ZeroClaimAmount();
error InvalidDeadline();
error ClaimsNotActive();
error AlreadyClaimed();
error ClaimPeriodEnded();
error InvalidJournalLength();
error InsufficientBalance();
error ZeroClaimantAddress();
error NotClaimant();
error ClaimsStillActive();
error ZeroWithdrawAddress();
error NoTokensToWithdraw();
error AirdropAlreadyClosed();
error InvalidMerkleRoot();
error NullifierMismatch();
error AirdropNotClosed();
error ZeroRescueAddress();
error NoTokensToRescue();
error SealTooLarge();
error EthDepositRejected();
error WrongAirdropContract();
error WrongChainId();
error DeadlineNotPassed();
error InvalidWithdrawAddress();
error RenounceDisabled();

struct GuestOutput {
    bytes32 merkleRoot;
    bytes32 nullifier;
    bytes20 claimantAddress;
    bytes20 airdropContract;
    uint256 chainId;
}

contract AnonymousAirdrop is Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant MAX_SEAL_SIZE = 256 * 1024;

    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    IERC20 public immutable token;
    bytes32 public immutable merkleRoot;
    uint256 public immutable amountPerClaim;
    uint256 public immutable claimDeadline;

    mapping(bytes32 => bool) public nullifiers;
    uint256 public totalClaimed;
    uint256 public totalClaimants;
    bool public claimsActive;
    bool public closed;

    event Claimed(bytes32 indexed nullifier, address indexed claimantAddress, uint256 amount);

    event ClaimsStarted();
    event ClaimsPaused();
    event AirdropClosed();
    event EmergencyWithdraw(address indexed to, uint256 amount);
    event TokensRescued(address indexed to, address indexed tokenContract, uint256 amount);
    event AirdropInitialized(
        address indexed verifier,
        bytes32 imageId,
        address indexed token,
        bytes32 merkleRoot,
        uint256 amountPerClaim,
        uint256 claimDeadline
    );

    /// @notice Deploy the airdrop contract
    /// @param _verifier RISC Zero verifier contract address
    /// @param _imageId Expected guest program image ID
    /// @param _token ERC20 token to distribute
    /// @param _merkleRoot Root of the eligible addresses Merkle tree
    /// @param _amountPerClaim Token amount per claim
    /// @param _claimDeadline Unix timestamp deadline (0 = no deadline)
    constructor(
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        IERC20 _token,
        bytes32 _merkleRoot,
        uint256 _amountPerClaim,
        uint256 _claimDeadline
    ) Ownable(msg.sender) {
        if (address(_verifier) == address(0)) revert ZeroVerifierAddress();
        if (_imageId == bytes32(0)) revert ZeroImageId();
        if (address(_token) == address(0)) revert ZeroTokenAddress();
        if (_merkleRoot == bytes32(0)) revert ZeroMerkleRoot();
        if (_amountPerClaim == 0) revert ZeroClaimAmount();
        if (_claimDeadline != 0 && _claimDeadline <= block.timestamp) revert InvalidDeadline();
        verifier = _verifier;
        imageId = _imageId;
        token = _token;
        merkleRoot = _merkleRoot;
        amountPerClaim = _amountPerClaim;
        claimDeadline = _claimDeadline;
        claimsActive = false;
        closed = false;

        emit AirdropInitialized(
            address(_verifier), _imageId, address(_token), _merkleRoot, _amountPerClaim, _claimDeadline
        );
    }

    /// @notice Claim tokens from the airdrop using a valid ZK proof
    /// @param seal The RISC Zero proof seal
    /// @param journal The journal output from the zkVM execution
    /// @param expectedNullifier The expected nullifier to prevent double claims
    function claim(bytes calldata seal, bytes calldata journal, bytes32 expectedNullifier) external nonReentrant {
        if (!claimsActive) revert ClaimsNotActive();
        if (nullifiers[expectedNullifier]) revert AlreadyClaimed();
        if (claimDeadline != 0 && block.timestamp > claimDeadline) revert ClaimPeriodEnded();
        if (seal.length > MAX_SEAL_SIZE) revert SealTooLarge();
        if (journal.length != 160) revert InvalidJournalLength();

        GuestOutput memory output = abi.decode(journal, (GuestOutput));

        if (output.merkleRoot != merkleRoot) revert InvalidMerkleRoot();
        if (output.nullifier != expectedNullifier) revert NullifierMismatch();
        if (address(output.claimantAddress) == address(0)) revert ZeroClaimantAddress();
        if (msg.sender != address(output.claimantAddress)) revert NotClaimant();
        if (address(output.airdropContract) != address(this)) revert WrongAirdropContract();
        if (output.chainId != block.chainid) revert WrongChainId();
        if (token.balanceOf(address(this)) < amountPerClaim) revert InsufficientBalance();

        verifier.verify(seal, imageId, sha256(journal));

        nullifiers[expectedNullifier] = true;
        totalClaimants++;

        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransfer(msg.sender, amountPerClaim);
        totalClaimed += balanceBefore - token.balanceOf(address(this));

        emit Claimed(expectedNullifier, address(output.claimantAddress), amountPerClaim);
    }

    /// @notice Start the claims phase, allowing users to claim tokens
    function startClaims() external onlyOwner {
        if (closed) revert AirdropAlreadyClosed();
        claimsActive = true;
        emit ClaimsStarted();
    }

    /// @notice Pause claims temporarily
    function pauseClaims() external onlyOwner {
        if (closed) revert AirdropAlreadyClosed();
        claimsActive = false;
        emit ClaimsPaused();
    }

    /// @notice Withdraw remaining tokens after claims are permanently closed
    /// @param to Address to receive the remaining tokens
    function emergencyWithdraw(address to) external onlyOwner nonReentrant {
        if (closed) revert AirdropAlreadyClosed();
        if (claimsActive) revert ClaimsStillActive();
        if (to == address(0)) revert ZeroWithdrawAddress();
        if (to == address(this)) revert InvalidWithdrawAddress();
        uint256 balanceBefore = token.balanceOf(address(this));
        if (balanceBefore == 0) revert NoTokensToWithdraw();
        closed = true;
        claimsActive = false;
        token.safeTransfer(to, balanceBefore);
        emit AirdropClosed();
        emit EmergencyWithdraw(to, balanceBefore - token.balanceOf(address(this)));
    }

    /// @notice Rescue ERC20 tokens sent to this contract after airdrop is closed
    ///         Can rescue any ERC20 including the airdrop token itself if re-sent after close.
    /// @param to Address to receive the rescued tokens
    /// @param tokenContract The ERC20 token contract to rescue
    function rescueTokens(address to, IERC20 tokenContract) external onlyOwner nonReentrant {
        if (!closed) revert AirdropNotClosed();
        if (to == address(0)) revert ZeroRescueAddress();
        if (to == address(this)) revert InvalidWithdrawAddress();
        uint256 balanceBefore = tokenContract.balanceOf(address(this));
        if (balanceBefore == 0) revert NoTokensToRescue();
        tokenContract.safeTransfer(to, balanceBefore);
        emit TokensRescued(to, address(tokenContract), balanceBefore - tokenContract.balanceOf(address(this)));
    }

    /// @notice Get the remaining token balance in the contract
    /// @return The number of tokens remaining
    function getRemainingTokens() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /// @notice Check if a nullifier has already been claimed
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been claimed
    function isClaimed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /// @notice Allow anyone to withdraw remaining tokens to the owner after the claim deadline has passed
    ///         Requires claims to be paused first. Tokens are sent to the current owner.
    function withdrawAfterDeadline() external nonReentrant {
        if (closed) revert AirdropAlreadyClosed();
        if (claimDeadline == 0 || block.timestamp <= claimDeadline) revert DeadlineNotPassed();
        if (claimsActive) revert ClaimsStillActive();
        address to = owner();
        if (to == address(0)) revert ZeroWithdrawAddress();
        if (to == address(this)) revert InvalidWithdrawAddress();
        uint256 balanceBefore = token.balanceOf(address(this));
        if (balanceBefore == 0) revert NoTokensToWithdraw();
        closed = true;
        token.safeTransfer(to, balanceBefore);
        emit AirdropClosed();
        emit EmergencyWithdraw(to, balanceBefore - token.balanceOf(address(this)));
    }

    /// @notice Disabled - ownership renunciation is not allowed to maintain a responsible party
    function renounceOwnership() public view override onlyOwner {
        revert RenounceDisabled();
    }

    fallback() external payable {
        revert EthDepositRejected();
    }

    receive() external payable {
        revert EthDepositRejected();
    }
}
