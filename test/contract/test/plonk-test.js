const { expect } = require("chai");

const input = require("./data/public.json");
const proof = require("./data/proof.json");

describe("Plonk", function() {
  it("Should return true when proof is correct", async function() {
    const verifierFactory = await ethers.getContractFactory("KeyedVerifier");
    const verifier = await verifierFactory.deploy();
    
    await verifier.deployed();

    expect(await verifier.verify_serialized_proof(input, proof)).to.equal(true);
  });
});
