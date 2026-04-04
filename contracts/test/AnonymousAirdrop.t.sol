// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier, Receipt} from "@risc0/IRiscZeroVerifier.sol";
import {
    AnonymousAirdrop,
    GuestOutput,
    ZeroVerifierAddress,
    ZeroImageId,
    ZeroTokenAddress,
    ZeroMerkleRoot,
    ZeroClaimAmount,
    InvalidDeadline,
    ClaimsNotActive,
    AlreadyClaimed,
    ClaimPeriodEnded,
    InvalidJournalLength,
    InsufficientBalance,
    ZeroClaimantAddress,
    NotClaimant,
    ClaimsStillActive,
    ZeroWithdrawAddress,
    NoTokensToWithdraw,
    AirdropAlreadyClosed,
    InvalidMerkleRoot,
    NullifierMismatch,
    AirdropNotClosed,
    ZeroRescueAddress,
    NoTokensToRescue,
    SealTooLarge,
    EthDepositRejected,
    WrongAirdropContract,
    WrongChainId,
    DeadlineNotPassed,
    RenounceDisabled
} from "../src/AnonymousAirdrop.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AnonymousAirdropTest is Test {
    AnonymousAirdrop public airdrop;
    ERC20Mock public token;

    IRiscZeroVerifier mockVerifier;
    bytes32 imageId;
    bytes32 merkleRoot;
    uint256 amountPerClaim = 1000 * 10 ** 18;
    uint256 claimDeadline = 0;

    address owner = address(0x1);
    address claimant = address(0x2);
    address nonOwner = address(0x3);

    function makeGuestOutput(bytes32 nullifier_, bytes20 claimant20_) internal view returns (GuestOutput memory) {
        return GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier_,
            claimantAddress: claimant20_,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });
    }

    function setUp() public {
        vm.startPrank(owner);
        token = new ERC20Mock("AirdropToken", "ADT", owner, 1000000 * 10 ** 18);

        mockVerifier = IRiscZeroVerifier(address(new MockVerifier()));
        imageId = bytes32(uint256(1));
        merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        airdrop = new AnonymousAirdrop(
            mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, claimDeadline
        );

        token.transfer(address(airdrop), 100000 * 10 ** 18);
        vm.stopPrank();
    }

    function testInitialState() public {
        assertEq(address(airdrop.token()), address(token));
        assertEq(airdrop.merkleRoot(), merkleRoot);
        assertEq(airdrop.amountPerClaim(), amountPerClaim);
        assertFalse(airdrop.claimsActive());
        assertEq(airdrop.owner(), owner);
        assertEq(airdrop.claimDeadline(), 0);
    }

    function testEmitsAirdropInitialized() public {
        vm.expectEmit(true, true, false, true);
        emit AnonymousAirdrop.AirdropInitialized(
            address(mockVerifier), imageId, address(token), merkleRoot, amountPerClaim, claimDeadline
        );
        new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, claimDeadline);
    }

    function testStartClaims() public {
        vm.prank(owner);
        airdrop.startClaims();
        assertTrue(airdrop.claimsActive());
    }

    function testStartClaimsIdempotent() public {
        vm.prank(owner);
        airdrop.startClaims();
        assertTrue(airdrop.claimsActive());

        vm.prank(owner);
        airdrop.startClaims();
        assertTrue(airdrop.claimsActive());
    }

    function testCannotStartClaimsAsNonOwner() public {
        vm.expectRevert();
        vm.prank(nonOwner);
        airdrop.startClaims();
    }

    function testCannotClaimBeforeStart() public {
        vm.expectRevert(ClaimsNotActive.selector);
        airdrop.claim("", "", bytes32(0));
    }

    function testPauseClaims() public {
        vm.prank(owner);
        airdrop.startClaims();
        assertTrue(airdrop.claimsActive());
        vm.prank(owner);
        airdrop.pauseClaims();
        assertFalse(airdrop.claimsActive());
    }

    function testPauseClaimsIdempotent() public {
        vm.prank(owner);
        airdrop.startClaims();

        vm.prank(owner);
        airdrop.pauseClaims();
        assertFalse(airdrop.claimsActive());

        vm.prank(owner);
        airdrop.pauseClaims();
        assertFalse(airdrop.claimsActive());
    }

    function testCannotPauseClaimsAsNonOwner() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.expectRevert();
        vm.prank(nonOwner);
        airdrop.pauseClaims();
    }

    function testEmergencyWithdraw() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        uint256 initialBalance = token.balanceOf(address(this));
        uint256 contractBalance = token.balanceOf(address(airdrop));

        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        assertEq(token.balanceOf(address(airdrop)), 0);
        assertEq(token.balanceOf(address(this)), initialBalance + contractBalance);
    }

    function testCannotEmergencyWithdrawWhenActive() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.expectRevert(ClaimsStillActive.selector);
        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));
    }

    function testCannotEmergencyWithdrawAsNonOwner() public {
        vm.prank(owner);
        airdrop.pauseClaims();
        vm.expectRevert();
        vm.prank(nonOwner);
        airdrop.emergencyWithdraw(address(this));
    }

    function testNullifierTracking() public {
        vm.prank(owner);
        airdrop.startClaims();
        bytes32 testNullifier = keccak256("test");
        assertFalse(airdrop.isClaimed(testNullifier));
    }

    function testSuccessfulClaim() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        bytes memory journal = abi.encode(makeGuestOutput(nullifier, claimant20));
        bytes memory seal = "";

        uint256 balanceBefore = token.balanceOf(claimant);

        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);

        assertEq(token.balanceOf(claimant), balanceBefore + amountPerClaim);
        assertTrue(airdrop.isClaimed(nullifier));
        assertEq(airdrop.totalClaimants(), 1);
        assertEq(airdrop.totalClaimed(), amountPerClaim);
    }

    function testCannotDoubleClaim() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        bytes memory journal = abi.encode(makeGuestOutput(nullifier, claimant20));
        bytes memory seal = "";

        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);

        vm.expectRevert(AlreadyClaimed.selector);
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithInvalidMerkleRoot() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: bytes32(uint256(0xDEADBEEF)),
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert(InvalidMerkleRoot.selector);
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithNullifierMismatch() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: keccak256("different-nullifier"),
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert(NullifierMismatch.selector);
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithInsufficientBalance() public {
        vm.startPrank(owner);
        AnonymousAirdrop lowBalanceAirdrop =
            new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, 0);

        token.transfer(address(lowBalanceAirdrop), amountPerClaim - 1);
        lowBalanceAirdrop.startClaims();
        vm.stopPrank();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(lowBalanceAirdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert(InsufficientBalance.selector);
        vm.prank(claimant);
        lowBalanceAirdrop.claim(seal, journal, nullifier);
    }

    function testGetRemainingTokens() public {
        uint256 balance = airdrop.getRemainingTokens();
        assertEq(balance, 100000 * 10 ** 18);
    }

    function testFuzz_ClaimMultipleUsers(uint8 numUsers) public {
        vm.assume(numUsers > 0 && numUsers <= 50);

        vm.prank(owner);
        airdrop.startClaims();

        uint256 totalExpected = 0;
        for (uint8 i = 0; i < numUsers; i++) {
            bytes32 nullifier = keccak256(abi.encodePacked("user", i));
            address user = address(uint160(uint256(keccak256(abi.encodePacked("addr", i)))));
            bytes20 user20 = bytes20(uint160(user));

            bytes memory journal = abi.encode(makeGuestOutput(nullifier, user20));
            bytes memory seal = "";

            vm.prank(user);
            airdrop.claim(seal, journal, nullifier);

            totalExpected += amountPerClaim;
        }

        assertEq(airdrop.totalClaimants(), numUsers);
        assertEq(airdrop.totalClaimed(), totalExpected);
    }

    function testCannotDeployWithZeroVerifier() public {
        vm.expectRevert(ZeroVerifierAddress.selector);
        new AnonymousAirdrop(
            IRiscZeroVerifier(address(0)), imageId, IERC20(address(token)), merkleRoot, amountPerClaim, claimDeadline
        );
    }

    function testCannotDeployWithZeroImageId() public {
        vm.expectRevert(ZeroImageId.selector);
        new AnonymousAirdrop(
            mockVerifier, bytes32(0), IERC20(address(token)), merkleRoot, amountPerClaim, claimDeadline
        );
    }

    function testCannotDeployWithZeroToken() public {
        vm.expectRevert(ZeroTokenAddress.selector);
        new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(0)), merkleRoot, amountPerClaim, claimDeadline);
    }

    function testCannotDeployWithZeroMerkleRoot() public {
        vm.expectRevert(ZeroMerkleRoot.selector);
        new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), bytes32(0), amountPerClaim, claimDeadline);
    }

    function testCannotDeployWithZeroAmount() public {
        vm.expectRevert(ZeroClaimAmount.selector);
        new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, 0, claimDeadline);
    }

    function testCannotEmergencyWithdrawToZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ZeroWithdrawAddress.selector);
        airdrop.emergencyWithdraw(address(0));
    }

    function testCannotClaimAsNonClaimant() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        bytes memory journal = abi.encode(makeGuestOutput(nullifier, claimant20));
        bytes memory seal = "";

        vm.expectRevert(NotClaimant.selector);
        vm.prank(nonOwner);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithZeroClaimantAddress() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: bytes20(address(0)),
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert(ZeroClaimantAddress.selector);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithInvalidJournalLength() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");

        vm.expectRevert(InvalidJournalLength.selector);
        airdrop.claim("", "short", nullifier);
    }

    function testCannotClaimWithWrongContract() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(0x9999))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert(WrongAirdropContract.selector);
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithWrongChainId() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid + 1
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert(WrongChainId.selector);
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotRenounceOwnership() public {
        vm.prank(owner);
        vm.expectRevert(RenounceDisabled.selector);
        airdrop.renounceOwnership();
    }

    function testCannotClaimWithOversizedSeal() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");

        bytes memory giantSeal = new bytes(256 * 1024 + 1);
        vm.expectRevert(SealTooLarge.selector);
        airdrop.claim(giantSeal, "", nullifier);
    }

    function testCannotSendEth() public {
        vm.expectRevert(EthDepositRejected.selector);
        (bool success,) = address(airdrop).call{value: 1 ether}("");
        success;
    }

    function testFallbackReverts() public {
        vm.expectRevert(EthDepositRejected.selector);
        (bool success,) = address(airdrop).call{value: 0}("nonExistentFunction()");
        success;
    }

    function testCannotEmergencyWithdrawAfterClose() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.prank(owner);
        airdrop.emergencyWithdraw(owner);

        vm.expectRevert(AirdropAlreadyClosed.selector);
        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));
    }

    function testCannotEmergencyWithdrawWithNoTokens() public {
        vm.startPrank(owner);
        AnonymousAirdrop unfundedAirdrop =
            new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, 0);

        vm.expectRevert(NoTokensToWithdraw.selector);
        unfundedAirdrop.emergencyWithdraw(owner);
        vm.stopPrank();
    }

    function testCannotEmergencyWithdrawTwice() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        token.transfer(address(airdrop), 1000 * 10 ** 18);

        vm.expectRevert(AirdropAlreadyClosed.selector);
        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));
    }

    function testCannotStartClaimsAfterEmergencyWithdraw() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        assertTrue(airdrop.closed());
        vm.expectRevert(AirdropAlreadyClosed.selector);
        vm.prank(owner);
        airdrop.startClaims();
    }

    function testCannotPauseClaimsAfterEmergencyWithdraw() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        assertTrue(airdrop.closed());
        vm.expectRevert(AirdropAlreadyClosed.selector);
        vm.prank(owner);
        airdrop.pauseClaims();
    }

    function testEmitsAirdropClosedEvent() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.expectEmit(true, false, false, true);
        emit AnonymousAirdrop.AirdropClosed();

        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));
    }

    function testRescueTokens() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();
        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        ERC20Mock otherToken = new ERC20Mock("Other", "OTH", owner, 10000 * 10 ** 18);
        vm.prank(owner);
        otherToken.transfer(address(airdrop), 500 * 10 ** 18);

        vm.prank(owner);
        airdrop.rescueTokens(owner, IERC20(address(otherToken)));

        assertEq(otherToken.balanceOf(address(airdrop)), 0);
        assertEq(otherToken.balanceOf(owner), 10000 * 10 ** 18);
    }

    function testCannotRescueTokensBeforeClose() public {
        vm.expectRevert(AirdropNotClosed.selector);
        vm.prank(owner);
        airdrop.rescueTokens(owner, IERC20(address(token)));
    }

    function testCannotRescueTokensToZeroAddress() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();
        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        vm.expectRevert(ZeroRescueAddress.selector);
        vm.prank(owner);
        airdrop.rescueTokens(address(0), IERC20(address(token)));
    }

    function testCannotRescueAirdropToken() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();
        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        vm.expectRevert(NoTokensToRescue.selector);
        vm.prank(owner);
        airdrop.rescueTokens(owner, IERC20(address(token)));
    }

    function testCannotRescueWithNoBalance() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();
        vm.prank(owner);
        airdrop.emergencyWithdraw(address(this));

        ERC20Mock otherToken = new ERC20Mock("Other", "OTH", owner, 10000 * 10 ** 18);

        vm.expectRevert(NoTokensToRescue.selector);
        vm.prank(owner);
        airdrop.rescueTokens(owner, IERC20(address(otherToken)));
    }
}

contract AnonymousAirdropDeadlineTest is Test {
    AnonymousAirdrop public airdrop;
    ERC20Mock public token;

    IRiscZeroVerifier mockVerifier;
    bytes32 imageId;
    bytes32 merkleRoot;
    uint256 amountPerClaim = 1000 * 10 ** 18;
    uint256 claimDeadline;

    address owner = address(0x1);
    address claimant = address(0x2);
    address nonOwner = address(0x3);

    function setUp() public {
        claimDeadline = block.timestamp + 30 days;

        vm.startPrank(owner);
        token = new ERC20Mock("AirdropToken", "ADT", owner, 1000000 * 10 ** 18);

        mockVerifier = IRiscZeroVerifier(address(new MockVerifier()));
        imageId = bytes32(uint256(1));
        merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        airdrop = new AnonymousAirdrop(
            mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, claimDeadline
        );

        token.transfer(address(airdrop), 100000 * 10 ** 18);
        vm.stopPrank();
    }

    function testDeadlineSet() public {
        assertEq(airdrop.claimDeadline(), claimDeadline);
    }

    function testCanClaimBeforeDeadline() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);

        assertEq(token.balanceOf(claimant), amountPerClaim);
    }

    function testCannotClaimAfterDeadline() public {
        vm.prank(owner);
        airdrop.startClaims();

        vm.warp(claimDeadline + 1);

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert(ClaimPeriodEnded.selector);
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCanClaimExactlyAtDeadline() public {
        vm.prank(owner);
        airdrop.startClaims();

        vm.warp(claimDeadline);

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);

        assertEq(token.balanceOf(claimant), amountPerClaim);
    }

    function testCannotDeployWithPastDeadline() public {
        vm.warp(1000);
        vm.expectRevert(InvalidDeadline.selector);
        new AnonymousAirdrop(
            mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, block.timestamp - 1
        );
    }

    function testCanDeployWithZeroDeadline() public {
        new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, 0);
    }

    function testWithdrawAfterDeadline() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.warp(claimDeadline + 1);

        uint256 ownerBalanceBefore = token.balanceOf(owner);
        uint256 contractBalance = token.balanceOf(address(airdrop));

        vm.prank(nonOwner);
        airdrop.withdrawAfterDeadline();

        assertTrue(airdrop.closed());
        assertEq(token.balanceOf(address(airdrop)), 0);
        assertEq(token.balanceOf(owner), ownerBalanceBefore + contractBalance);
    }

    function testCannotWithdrawAfterDeadlineBeforeDeadline() public {
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.expectRevert(DeadlineNotPassed.selector);
        vm.prank(nonOwner);
        airdrop.withdrawAfterDeadline();
    }

    function testCannotWithdrawAfterDeadlineWhenActive() public {
        vm.prank(owner);
        airdrop.startClaims();

        vm.warp(claimDeadline + 1);

        vm.expectRevert(ClaimsStillActive.selector);
        vm.prank(nonOwner);
        airdrop.withdrawAfterDeadline();
    }

    function testCannotWithdrawAfterDeadlineNoDeadline() public {
        AnonymousAirdrop noDeadlineAirdrop =
            new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, amountPerClaim, 0);

        vm.expectRevert(DeadlineNotPassed.selector);
        noDeadlineAirdrop.withdrawAfterDeadline();
    }

    function testCannotWithdrawAfterDeadlineWhenClosed() public {
        vm.prank(owner);
        airdrop.startClaims();
        vm.prank(owner);
        airdrop.pauseClaims();

        vm.prank(owner);
        airdrop.emergencyWithdraw(owner);

        vm.warp(claimDeadline + 1);

        vm.expectRevert(AirdropAlreadyClosed.selector);
        vm.prank(nonOwner);
        airdrop.withdrawAfterDeadline();
    }
}

contract MockVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure {}
    function verifyIntegrity(Receipt calldata) external pure {}
}

contract ERC20Mock is ERC20 {
    constructor(string memory name, string memory symbol, address to, uint256 amount) ERC20(name, symbol) {
        _mint(to, amount);
    }
}

contract MaliciousERC20 is ERC20 {
    AnonymousAirdrop public target;
    bytes public attackSeal;
    bytes public attackJournal;
    bytes32 public attackNullifier;
    bool public attacking;

    constructor(string memory name, string memory symbol, address to, uint256 amount) ERC20(name, symbol) {
        _mint(to, amount);
    }

    function setAttackParams(
        AnonymousAirdrop _target,
        bytes calldata _seal,
        bytes calldata _journal,
        bytes32 _nullifier
    ) external {
        target = _target;
        attackSeal = _seal;
        attackJournal = _journal;
        attackNullifier = _nullifier;
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        if (!attacking && address(target) != address(0)) {
            attacking = true;
            try target.claim(attackSeal, attackJournal, attackNullifier) {} catch {}
            attacking = false;
        }
        return super.transfer(to, amount);
    }
}

contract ReentrancyTest is Test {
    MaliciousERC20 public token;
    AnonymousAirdrop public airdrop;
    IRiscZeroVerifier mockVerifier;

    address owner = address(0x1);
    address claimant = address(0x2);

    function setUp() public {
        vm.startPrank(owner);
        token = new MaliciousERC20("BadToken", "BAD", owner, 1000000 * 10 ** 18);

        mockVerifier = IRiscZeroVerifier(address(new MockVerifier()));
        bytes32 imageId = bytes32(uint256(1));
        bytes32 merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        airdrop = new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, 1000 * 10 ** 18, 0);

        token.transfer(address(airdrop), 100000 * 10 ** 18);
        vm.stopPrank();
    }

    function testReentrancyBlocked() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("reentrancy-test");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: airdrop.merkleRoot(),
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        token.setAttackParams(airdrop, seal, journal, nullifier);

        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
        assertTrue(airdrop.isClaimed(nullifier));
        assertEq(airdrop.totalClaimants(), 1);
        assertEq(airdrop.totalClaimed(), 1000 * 10 ** 18);
    }
}

contract AirdropHandler is Test {
    AnonymousAirdrop public airdrop;
    ERC20Mock public token;
    address public owner;

    uint256 public ghost_totalClaimed;
    uint256 public ghost_totalClaimants;

    constructor(AnonymousAirdrop _airdrop, ERC20Mock _token, address _owner) {
        airdrop = _airdrop;
        token = _token;
        owner = _owner;
    }

    function claim(bytes32 nullifier, address claimant_) external {
        if (!airdrop.claimsActive()) return;
        if (airdrop.claimDeadline() != 0 && block.timestamp > airdrop.claimDeadline()) return;
        if (airdrop.isClaimed(nullifier)) return;
        if (claimant_ == address(0)) return;

        bytes20 claimant20 = bytes20(uint160(claimant_));
        GuestOutput memory output = GuestOutput({
            merkleRoot: airdrop.merkleRoot(),
            nullifier: nullifier,
            claimantAddress: claimant20,
            airdropContract: bytes20(uint160(address(airdrop))),
            chainId: block.chainid
        });

        bytes memory journal = abi.encode(output);

        vm.prank(claimant_);
        try airdrop.claim("", journal, nullifier) {
            ghost_totalClaimed += airdrop.amountPerClaim();
            ghost_totalClaimants++;
        } catch {}
    }

    function startClaims() external {
        if (airdrop.closed()) return;
        vm.prank(owner);
        try airdrop.startClaims() {} catch {}
    }

    function pauseClaims() external {
        if (airdrop.closed()) return;
        vm.prank(owner);
        try airdrop.pauseClaims() {} catch {}
    }
}

contract AnonymousAirdropInvariantTest is Test {
    AnonymousAirdrop public airdrop;
    ERC20Mock public token;
    AirdropHandler public handler;

    address owner = address(0x1);

    function setUp() public {
        vm.startPrank(owner);
        token = new ERC20Mock("AirdropToken", "ADT", owner, 1_000_000 * 10 ** 18);

        IRiscZeroVerifier mockVerifier = IRiscZeroVerifier(address(new MockVerifier()));
        bytes32 imageId = bytes32(uint256(1));
        bytes32 merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        airdrop = new AnonymousAirdrop(mockVerifier, imageId, IERC20(address(token)), merkleRoot, 1000 * 10 ** 18, 0);

        token.transfer(address(airdrop), 100_000 * 10 ** 18);
        vm.stopPrank();

        handler = new AirdropHandler(airdrop, token, owner);

        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = handler.claim.selector;
        selectors[1] = handler.startClaims.selector;
        selectors[2] = handler.pauseClaims.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_totalClaimedNeverExceedsDeposits() public view {
        assertLe(airdrop.totalClaimed(), 100_000 * 10 ** 18);
    }

    function invariant_totalClaimantsConsistentWithTotalClaimed() public view {
        if (airdrop.totalClaimants() == 0) {
            assertEq(airdrop.totalClaimed(), 0);
        } else {
            assertEq(airdrop.totalClaimed(), airdrop.totalClaimants() * airdrop.amountPerClaim());
        }
    }

    function invariant_closedImpliesNotActive() public view {
        if (airdrop.closed()) {
            assertFalse(airdrop.claimsActive());
        }
    }

    function invariant_claimantsAndClaimedConsistent() public view {
        assertEq(airdrop.totalClaimants() > 0, airdrop.totalClaimed() > 0);
    }
}
