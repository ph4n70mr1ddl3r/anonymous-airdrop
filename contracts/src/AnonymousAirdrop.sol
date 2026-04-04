// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IRiscZeroVerifier} from "@risc0/IRiscZeroVerifier.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

struct GuestOutput {
    bytes32 merkleRoot;
    bytes32 nullifier;
    bytes20 claimantAddress;
}

contract AnonymousAirdrop is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

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

    event Claimed(
        bytes32 indexed nullifier,
        address indexed claimantAddress,
        uint256 amount
    );

    event ClaimsStarted();
    event ClaimsPaused();
    event EmergencyWithdraw(address indexed to, uint256 amount);
    event AirdropInitialized(
        address indexed verifier,
        bytes32 imageId,
        address indexed token,
        bytes32 merkleRoot,
        uint256 amountPerClaim,
        uint256 claimDeadline
    );

    constructor(
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        IERC20 _token,
        bytes32 _merkleRoot,
        uint256 _amountPerClaim,
        uint256 _claimDeadline
    ) Ownable(msg.sender) {
        require(address(_verifier) != address(0), "zero verifier address");
        require(_imageId != bytes32(0), "zero image ID");
        require(address(_token) != address(0), "zero token address");
        require(_merkleRoot != bytes32(0), "zero merkle root");
        require(_amountPerClaim > 0, "zero claim amount");
        require(_claimDeadline == 0 || _claimDeadline > block.timestamp, "deadline must be future or zero");
        verifier = _verifier;
        imageId = _imageId;
        token = _token;
        merkleRoot = _merkleRoot;
        amountPerClaim = _amountPerClaim;
        claimDeadline = _claimDeadline;
        claimsActive = false;

        emit AirdropInitialized(
            address(_verifier),
            _imageId,
            address(_token),
            _merkleRoot,
            _amountPerClaim,
            _claimDeadline
        );
    }

    /// @notice Claim tokens from the airdrop using a valid ZK proof
    /// @param seal The RISC Zero proof seal
    /// @param journal The journal output from the zkVM execution
    /// @param expectedNullifier The expected nullifier to prevent double claims
    function claim(
        bytes calldata seal,
        bytes calldata journal,
        bytes32 expectedNullifier
    ) external nonReentrant {
        require(claimsActive, "Claims not active");
        require(!nullifiers[expectedNullifier], "Already claimed");
        require(claimDeadline == 0 || block.timestamp <= claimDeadline, "Claim period ended");
        require(token.balanceOf(address(this)) >= amountPerClaim, "Insufficient airdrop balance");

        verifier.verify(seal, imageId, sha256(journal));

        GuestOutput memory output = abi.decode(journal, (GuestOutput));

        require(output.merkleRoot == merkleRoot, "Invalid merkle root");
        require(output.nullifier == expectedNullifier, "Nullifier mismatch");
        require(address(output.claimantAddress) != address(0), "zero claimant address");
        require(msg.sender == address(output.claimantAddress), "Not claimant");

        nullifiers[expectedNullifier] = true;
        totalClaimed += amountPerClaim;
        totalClaimants++;

        token.safeTransfer(output.claimantAddress, amountPerClaim);

        emit Claimed(
            expectedNullifier,
            address(output.claimantAddress),
            amountPerClaim
        );
    }

    /// @notice Start the claims phase, allowing users to claim tokens
    function startClaims() external onlyOwner {
        claimsActive = true;
        emit ClaimsStarted();
    }

    /// @notice Pause claims temporarily
    function pauseClaims() external onlyOwner {
        claimsActive = false;
        emit ClaimsPaused();
    }

    /// @notice Withdraw remaining tokens after claims are permanently closed
    /// @param to Address to receive the remaining tokens
    function emergencyWithdraw(address to) external onlyOwner nonReentrant {
        require(!claimsActive, "Claims still active");
        require(to != address(0), "zero withdraw address");
        uint256 balance = token.balanceOf(address(this));
        require(balance > 0, "No tokens to withdraw");
        token.safeTransfer(to, balance);
        emit EmergencyWithdraw(to, balance);
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
}
