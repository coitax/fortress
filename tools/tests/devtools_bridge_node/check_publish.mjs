// Fails while the Node SDK publishes container port 9222 on every host address.
import { readFileSync } from "node:fs";
import { Fortress } from "../../../sdk/node/index.js";

const f = new Fortress({ port: 9222 });
f._startDocker();

const lines = readFileSync(process.env.FORTRESS_TEST_CAPTURE, "utf8")
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line));
const run = lines.find((call) => call.cmd === "docker" && call.args?.[0] === "run");
if (!run) {
  console.error("SDK did not call docker run", lines);
  process.exit(1);
}
const flag = run.args.indexOf("-p");
const spec = flag >= 0 ? run.args[flag + 1] : "";
const loopback = spec.startsWith("127.0.0.1:") || spec.startsWith("[::1]:");
if (!loopback) {
  console.error(`docker publish is not bound to host loopback: ${spec}`);
  process.exit(1);
}
