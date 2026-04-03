// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "@risc0/IRiscZeroVerifier.sol";
import {AnonymousAirdrop} from "../src/AnonymousAirdrop.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AnonymousAirdropTest is Test {
    AnonymousAirdrop public airdrop;
    ERC20Mock public token;

    IRiscZeroVerifier mockVerifier;
    bytes32 imageId;
    bytes32 merkleRoot;
    uint256 amountPerClaim = 1000 * 10**18;

    function setUp() public {
        token = new ERC20Mock("AirdropToken", "ADT", address(this), 1000000 * 10**18);

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
    }

    function testInitialState() public {
        assertEq(address(airdrop.token()), address(token));
        assertEq(airdrop.merkleRoot(), merkleRoot);
        assertEq(airdrop.amountPerClaim(), amountPerClaim);
        assertFalse(airdrop.claimsActive());
    }

    function testStartClaims() public {
        airdrop.startClaims();
        assertTrue(airdrop.claimsActive());
    }

    function testCannotClaimBeforeStart() public {
        vm.expectRevert("Claims not active");
        airdrop.claim("", "", bytes32(0));
    }

    function testPauseClaims() public {
        airdrop.startClaims();
        assertTrue(airdrop.claimsActive());
        airdrop.pauseClaims();
        assertFalse(airdrop.claimsActive());
    }

    function testEmergencyWithdraw() public {
        uint256 initialBalance = token.balanceOf(address(this));
        uint256 contractBalance = token.balanceOf(address(airdrop));

        airdrop.emergencyWithdraw(address(this));

        assertEq(token.balanceOf(address(airdrop)), 0);
        assertEq(token.balanceOf(address(this)), initialBalance + contractBalance);
    }

    function testNullifierTracking() public {
        airdrop.startClaims();
        bytes32 testNullifier = keccak256("test");
        assertFalse(airdrop.isClaimed(testNullifier));
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
