// Test double for node:child_process. Records every spawnSync the SDK makes
// while the publish-address check imports it. Not used by the product.
import { appendFileSync } from "node:fs";

export function spawn() {
  throw new Error("spawn is not used by the Docker publish check");
}

export function spawnSync(cmd, args) {
  appendFileSync(process.env.FORTRESS_TEST_CAPTURE, JSON.stringify({ cmd, args }) + "\n");
  return { status: 0 };
}
