// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IRiscZeroVerifier} from "@risc0/IRiscZeroVerifier.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

struct GuestOutput {
    bytes32 merkleRoot;
    bytes32 nullifier;
    bytes20 claimantAddress;
}

contract AnonymousAirdrop {
    using SafeERC20 for IERC20;

    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;
    IERC20 public immutable token;
    bytes32 public immutable merkleRoot;
    uint256 public immutable amountPerClaim;

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

    constructor(
        IRiscZeroVerifier _verifier,
        bytes32 _imageId,
        IERC20 _token,
        bytes32 _merkleRoot,
        uint256 _amountPerClaim
    ) {
        verifier = _verifier;
        imageId = _imageId;
        token = _token;
        merkleRoot = _merkleRoot;
        amountPerClaim = _amountPerClaim;
        claimsActive = false;
    }

    function claim(
        bytes calldata seal,
        bytes calldata journal,
        bytes32 expectedNullifier
    ) external {
        require(claimsActive, "Claims not active");
        require(!nullifiers[expectedNullifier], "Already claimed");

        verifier.verify(seal, imageId, sha256(journal));

        GuestOutput memory output = abi.decode(journal, (GuestOutput));

        require(output.merkleRoot == merkleRoot, "Invalid merkle root");
        require(output.nullifier == expectedNullifier, "Nullifier mismatch");

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

    function startClaims() external {
        claimsActive = true;
        emit ClaimsStarted();
    }

    function pauseClaims() external {
        claimsActive = false;
        emit ClaimsPaused();
    }

    function emergencyWithdraw(address to) external {
        uint256 balance = token.balanceOf(address(this));
        token.safeTransfer(to, balance);
        emit EmergencyWithdraw(to, balance);
    }

    function getRemainingTokens() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function isClaimed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }
}
