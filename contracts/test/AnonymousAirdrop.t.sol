// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "@risc0/IRiscZeroVerifier.sol";
import {AnonymousAirdrop, GuestOutput} from "../src/AnonymousAirdrop.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AnonymousAirdropTest is Test {
    AnonymousAirdrop public airdrop;
    ERC20Mock public token;

    IRiscZeroVerifier mockVerifier;
    bytes32 imageId;
    bytes32 merkleRoot;
    uint256 amountPerClaim = 1000 * 10**18;

    address owner = address(0x1);
    address claimant = address(0x2);
    address nonOwner = address(0x3);

    function setUp() public {
        vm.startPrank(owner);
        token = new ERC20Mock("AirdropToken", "ADT", owner, 1000000 * 10**18);

        mockVerifier = IRiscZeroVerifier(address(new MockVerifier()));
        imageId = bytes32(0);
        merkleRoot = bytes32(0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);

        airdrop = new AnonymousAirdrop(
            mockVerifier,
            imageId,
            IERC20(address(token)),
            merkleRoot,
            amountPerClaim
        );

        token.transfer(address(airdrop), 100000 * 10**18);
        vm.stopPrank();
    }

    function testInitialState() public {
        assertEq(address(airdrop.token()), address(token));
        assertEq(airdrop.merkleRoot(), merkleRoot);
        assertEq(airdrop.amountPerClaim(), amountPerClaim);
        assertFalse(airdrop.claimsActive());
        assertEq(airdrop.owner(), owner);
    }

    function testStartClaims() public {
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
        vm.expectRevert("Claims not active");
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

    function testCannotPauseClaimsAsNonOwner() public {
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
        vm.expectRevert("Claims still active");
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
        bytes32 claimantAddr = bytes32(uint256(uint160(claimant)));
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20
        });

        bytes memory journal = abi.encode(output);
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

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);

        vm.expectRevert("Already claimed");
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithInvalidMerkleRoot() public {
        vm.prank(owner);
        airdrop.startClaims();

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: bytes32(0xDEADBEEF),
            nullifier: nullifier,
            claimantAddress: claimant20
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert("Invalid merkle root");
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
            claimantAddress: claimant20
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert("Nullifier mismatch");
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testCannotClaimWithInsufficientBalance() public {
        vm.prank(owner);
        airdrop.startClaims();

        vm.prank(owner);
        IERC20(address(token)).transfer(address(0x4), token.balanceOf(address(airdrop)) - 1);

        bytes32 nullifier = keccak256("test-nullifier");
        bytes20 claimant20 = bytes20(uint160(claimant));

        GuestOutput memory output = GuestOutput({
            merkleRoot: merkleRoot,
            nullifier: nullifier,
            claimantAddress: claimant20
        });

        bytes memory journal = abi.encode(output);
        bytes memory seal = "";

        vm.expectRevert("Insufficient airdrop balance");
        vm.prank(claimant);
        airdrop.claim(seal, journal, nullifier);
    }

    function testGetRemainingTokens() public {
        uint256 balance = airdrop.getRemainingTokens();
        assertEq(balance, 100000 * 10**18);
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

            GuestOutput memory output = GuestOutput({
                merkleRoot: merkleRoot,
                nullifier: nullifier,
                claimantAddress: user20
            });

            bytes memory journal = abi.encode(output);
            bytes memory seal = "";

            vm.prank(user);
            airdrop.claim(seal, journal, nullifier);

            totalExpected += amountPerClaim;
        }

        assertEq(airdrop.totalClaimants(), numUsers);
        assertEq(airdrop.totalClaimed(), totalExpected);
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
