const { expect } = require("chai");

const proof = require("./data/proof.json");

describe("Plonk", function() {
  it("Should return true when proof is correct", async function() {
    const verifierFactory = await ethers.getContractFactory("KeysWithPlonkVerifier");
    const verifier = await verifierFactory.deploy();
    
    await verifier.deployed();

    expect(await verifier.verifyAggregatedProof(proof[0], proof[1], proof[2], proof[3], proof[4])).to.equal(true);
  });
});
