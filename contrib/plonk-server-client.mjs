import * as fs from 'fs';
import caller from "grpc-caller";
const file = "../proto/server.proto";

const load = {
  keepCase: true,
  longs: String,
  defaults: false,
};
const server = process.env.GRPC_SERVER || "localhost:50055";
console.log("using grpc", server);
const client = caller(`${server}`, { file, load }, "PlonkitServer");

var task_cnt = 0

export async function prove(witness_fn) {
  const result = (await client.Prove({ 
    task_id: `task ${task_cnt}`,
    witness: fs.readFileSync(witness_fn || 'witness.wtns'),
  }));

  task_cnt = task_cnt + 1;

  return result;
}

export async function status() {
  return await client.Status({});
}
