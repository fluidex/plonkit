import * as w from "../node_modules/snarkjs/src/wtns_utils.js";
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

async function main() {
  const wit = await w.read(circuitDir + "/witness.wtns");
  for (var idx in wit) {
    wit[idx] = wit[idx].toString();
  }
  fs.writeFileSync(circuitDir + "/witness.json", JSON.stringify(wit), "utf8");
}

main().catch(err => {
  console.log(err);
  process.exit(1);
});
