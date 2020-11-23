import * as w from "./node_modules/snarkjs/src/wtns_utils.js";
import fs from "fs";
import process from "process";

const negOne =
  "21888242871839275222246405745257275088548364400416034343698204186575808495616";

const circuitDir = process.argv[2];
if (circuitDir == null) {
  const fileName = __filename.split("/").pop();
  console.log(`
usage: node ${fileName} circuitDir
example: node ${fileName} testdata/poseidon
`);
  process.exit(1);
}
console.log("process circuit inside ", circuitDir);
function loadJson(fileName) {
  return JSON.parse(fs.readFileSync(fileName, { encoding: "utf8" }));
}
let circuitJson = loadJson(circuitDir + "/" + "circuit.r1cs.json");

function getUnconstrainedVar(circuitJson) {
  let constrainedVars = new Set();
  let unconstrainedVars = [];
  for (let c of circuitJson.constraints) {
    for (let item of c) {
      for (let elem in item) {
        constrainedVars.add(elem);
      }
    }
  }
  for (let idx = 0; idx < circuitJson.nVars; idx++) {
    if (!constrainedVars.has(idx.toString())) {
      unconstrainedVars.push(idx.toString());
    }
  }
  return unconstrainedVars;
}

async function main() {
  const unconstrainedVars = getUnconstrainedVar(circuitJson);
  for (let v of unconstrainedVars) {
    // (v*(-1) + 1*1)*(1*1) = 0, so v is constrainted to 1 here
    circuitJson.constraints.push([{ [v]: negOne, "0": "1" }, { "0": "1" }, {}]);
  }
  fs.writeFileSync(
    circuitDir + "/circuit.r1cs.json",
    JSON.stringify(circuitJson, null, 2),
    "utf8"
  );
  const wit = await w.read(circuitDir + "/witness.wtns");
  for (var idx in wit) {
    if (unconstrainedVars.includes(idx)) {
      wit[idx] = "1";
    } else {
      wit[idx] = wit[idx].toString();
    }
  }
  fs.writeFileSync(circuitDir + "/witness.json", JSON.stringify(wit), "utf8");
}

main().catch(err => {
  console.log(err);
  process.exit(1);
});
