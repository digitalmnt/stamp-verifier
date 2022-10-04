// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import "hardhat/console.sol";

contract VerifySignature {
    address public verifier;
    mapping(string => bool) public verifiedStamps;

    constructor(address _verifier) {
        verifier = _verifier;
    }

    function getMessageHash(
        address passportOwner,
        string memory credentialId,
        bool verified
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(passportOwner, credentialId, verified));
    }

    function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    function verify(
        address passportOwner,
        string memory credentialId,
        bool verified,
        bytes memory signature
    ) public {
        bytes32 messageHash = getMessageHash(passportOwner, credentialId, verified);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        if (recoverSigner(ethSignedMessageHash, signature) == verifier) {
            verifiedStamps[credentialId] = true;
        }
    }

    function isVerified(string memory stampId) public view returns (bool) {
        return verifiedStamps[stampId];
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }
}
