const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("VerifySignature", function () {
  it("should check signature", async function () {
    const accounts = await ethers.getSigners(2);

    const VerifySignature = await ethers.getContractFactory("VerifySignature");
    const verifySignature = await VerifySignature.deploy(accounts[0].address);
    await verifySignature.deployed();

    // address _signer,
    // address passportOwner
    // bytes32 credentialId,
    // bool verified
    // bytes memory signature

    const signer = accounts[0];
    const passportOwner = accounts[1].address;
    const credentialId =
      "did:pkh:eip155:1:0xe4c81FCb008E04C9bc5AD607f0cb14E4AC07896d";

    const hash = await verifySignature.getMessageHash(
      passportOwner,
      credentialId,
      true
    );

    const signature = await signer.signMessage(ethers.utils.arrayify(hash));
    const asdf = await verifySignature.verify(
      passportOwner,
      credentialId,
      true,
      signature
    );

    await verifySignature.verify(passportOwner, credentialId, true, signature);
    expect(await verifySignature.isVerified(credentialId)).to.equal(true);

    const unverifiedCredential =
      "did:pkh:eip155:1:0xe4c81FCb008E04C9bc5AD607f0cb14E4AC07896d";
    await verifySignature.verify(
      passportOwner,
      unverifiedCredential,
      false,
      signature
    );
    expect(await verifySignature.isVerified(credentialId)).to.equal(true);
  });
});
