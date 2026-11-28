// Cache-hit launches must not execute an unverified browser launcher.
//
// ensureNative() returns the cached launcher as soon as the file exists, before
// SHA256SUMS is fetched. Fortress.start and the tilion-fortress CLI then spawn
// that path. These tests fail while that short-circuit is present. A fix has to
// refuse a launcher that is not the published bundle, must not run or modify
// that file before refusing, and must not spawn a path inside the cache after a
// successful check — the file can be replaced between the check and the exec.
// Docker fallback does not use this launcher and is not covered here.
//
// Run:  node --test sdk/node/test/cache_short_circuit.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync,
  rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import http from "node:http";

const require = createRequire(import.meta.url);
const cp = require("node:child_process");
const origSpawn = cp.spawn;
const origSpawnSync = cp.spawnSync;
// Mutable so a test can replace a cache executable at the moment it is spawned.
// Installed before index.js is imported: that module's spawn binding calls through here.
const race = { fn: null };
function guard(orig) {
  return function guarded(file, args, opts) {
    if (race.fn) race.fn(file, args, opts);
    return orig.call(this, file, args, opts);
  };
}
cp.spawn = guard(origSpawn);
cp.spawnSync = guard(origSpawnSync);

const cacheRoot = mkdtempSync(join(tmpdir(), "fortress-node-cache-"));
process.env.FORTRESS_BROWSERS_PATH = cacheRoot;
const { Fortress, ASSETS, CHANNELS } = await import("../index.js");
const sdkNode = join(import.meta.dirname, "..");

function resetCache() {
  rmSync(cacheRoot, { recursive: true, force: true });
  mkdirSync(cacheRoot, { recursive: true });
  race.fn = null;
}

function cdpScript(marker) {
  return `#!/usr/bin/env python3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
with open(${JSON.stringify(marker)}, "w") as fh:
    fh.write("executed")
port = 9
for arg in sys.argv[1:]:
    if arg.startswith("--remote-debugging-port="):
        port = int(arg.split("=", 1)[1])

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"webSocketDebuggerUrl":"ws://127.0.0.1/planted"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        return
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
`;
}

function markerScript(marker, text) {
  return `#!/usr/bin/env python3
with open(${JSON.stringify(marker)}, "w") as fh:
    fh.write(${JSON.stringify(text)})
`;
}

function launcherPath(tag, plat) {
  return join(cacheRoot, tag, plat, ASSETS[plat].launcher);
}

function plant(tag, plat, body) {
  const path = launcherPath(tag, plat);
  mkdirSync(join(path, ".."), { recursive: true });
  if (existsSync(path)) rmSync(path);
  writeFileSync(path, body);
  chmodSync(path, 0o755);
  return path;
}

function underCache(file) {
  const rel = resolve(file);
  const root = resolve(cacheRoot);
  return rel === root || rel.startsWith(root + "/");
}

function listen(gets, headOk) {
  const hits = [];
  const server = http.createServer((req, res) => {
    const name = (req.url || "/").split("?")[0].replace(/^\//, "");
    hits.push(`${req.method} ${name}`);
    if (req.method === "HEAD") {
      if (!headOk.has(name) && !gets.has(name)) {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Length": (gets.get(name) || Buffer.alloc(0)).length });
      res.end();
      return;
    }
    const body = gets.get(name);
    if (!body) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Length": body.length });
    res.end(body);
  });
  return new Promise((resolveListen) => {
    server.listen(0, "127.0.0.1", () => {
      resolveListen({
        server,
        hits,
        host: `http://127.0.0.1:${server.address().port}`,
      });
    });
  });
}

function mismatchSums(asset) {
  const digest = createHash("sha256").update("unrelated-archive").digest("hex");
  return Buffer.from(`${digest}  ${asset}\n`);
}

function archiveFor(plat, script, dir) {
  const stage = join(dir, "stage");
  const rel = ASSETS[plat].launcher;
  const file = join(stage, rel);
  mkdirSync(join(file, ".."), { recursive: true });
  writeFileSync(file, script);
  chmodSync(file, 0o755);
  const archive = join(dir, ASSETS[plat].asset);
  if (ASSETS[plat].kind === "tar") {
    origSpawnSync("tar", ["-czf", archive, "-C", stage, "tilion-fortress"], { stdio: "ignore" });
  } else {
    origSpawnSync("python3", ["-c", `
import zipfile, sys
z = zipfile.ZipFile(sys.argv[1], "w")
z.write(sys.argv[2], sys.argv[3])
z.close()
`, archive, file, rel], { stdio: "ignore" });
  }
  return readFileSync(archive);
}

function withPlatform(platform, arch, fn) {
  const prev = {
    platform: Object.getOwnPropertyDescriptor(process, "platform"),
    arch: Object.getOwnPropertyDescriptor(process, "arch"),
  };
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  Object.defineProperty(process, "arch", { value: arch, configurable: true });
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      Object.defineProperty(process, "platform", prev.platform);
      Object.defineProperty(process, "arch", prev.arch);
    });
}

async function expectRefusedStart({ channel, plat, platform, arch, link }) {
  resetCache();
  const tag = CHANNELS[channel].tag;
  const asset = ASSETS[plat].asset;
  const marker = join(tmpdir(), `fortress-node-exec-${plat}-${channel}-${process.pid}`);
  rmSync(marker, { force: true });
  const dir = mkdtempSync(join(tmpdir(), "fortress-node-srv-"));
  const gets = new Map([["SHA256SUMS", mismatchSums(asset)]]);
  const headOk = new Set([asset]);
  const srv = await listen(gets, headOk);
  process.env.FORTRESS_DOWNLOAD_HOST = srv.host;
  const body = cdpScript(marker);
  let launcher;
  if (link) {
    const target = join(dir, "outside-payload");
    writeFileSync(target, body);
    chmodSync(target, 0o755);
    launcher = launcherPath(tag, plat);
    mkdirSync(join(launcher, ".."), { recursive: true });
    symlinkSync(target, launcher);
  } else {
    launcher = plant(tag, plat, body);
  }
  const before = link ? readlinkSync(launcher) : readFileSync(launcher);
  const port = 28000 + Math.floor(Math.random() * 10000);
  const run = async () => {
    const f = new Fortress({ port, channel, headless: true });
    let err = null;
    try {
      await f.start();
    } catch (e) {
      err = e;
    }
    await new Promise((r) => setTimeout(r, 300));
    try {
      if (existsSync(marker) || err === null) {
        throw new Error(
          `planted launcher was executed without a matching published digest; ` +
          `hits=${srv.hits.join(",")} marker=${existsSync(marker)} err=${err && err.message}`,
        );
      }
      if (String(err.message).includes("Docker") || f.dockerName) {
        throw new Error(`start() left the native launcher path: ${err.message}`);
      }
      if (link) assert.equal(readlinkSync(launcher), before);
      else assert.deepEqual(readFileSync(launcher), before);
    } finally {
      await f.close();
    }
  };
  try {
    if (platform) await withPlatform(platform, arch, run);
    else await run();
  } finally {
    srv.server.close();
    rmSync(dir, { recursive: true, force: true });
    rmSync(marker, { force: true });
  }
}

test("start refuses a preseeded linux launcher for both channels", async () => {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error(`linux cache path is not the one start() uses here: ${process.platform}/${process.arch}`);
  }
  for (const channel of ["stable", "latest"]) {
    await expectRefusedStart({ channel, plat: "linux-x64" });
  }
});

test("start refuses a preseeded mac launcher", async () => {
  await expectRefusedStart({
    channel: "stable", plat: "mac-arm64", platform: "darwin", arch: "arm64",
  });
  await expectRefusedStart({
    channel: "stable", plat: "mac-x64", platform: "darwin", arch: "x64",
  });
});

test("startNative does not execute a preseeded windows launcher", async () => {
  // Called directly so Node stays on the Linux shell implementation of shell:true.
  // Overriding process.platform to win32 makes Node look up cmd.exe instead.
  resetCache();
  const plat = "win-x64";
  const channel = "stable";
  const tag = CHANNELS[channel].tag;
  const marker = join(tmpdir(), `fortress-node-win-${process.pid}`);
  rmSync(marker, { force: true });
  const gets = new Map([["SHA256SUMS", mismatchSums(ASSETS[plat].asset)]]);
  const srv = await listen(gets, new Set([ASSETS[plat].asset]));
  process.env.FORTRESS_DOWNLOAD_HOST = srv.host;
  const launcher = plant(tag, plat, markerScript(marker, "executed"));
  const before = readFileSync(launcher);
  const f = new Fortress({ port: 29222, channel, headless: true });
  let err = null;
  try {
    await f._startNative(plat);
  } catch (e) {
    err = e;
  }
  await new Promise((r) => setTimeout(r, 300));
  try {
    if (existsSync(marker) || err === null) {
      throw new Error(
        `planted Windows launcher was executed; hits=${srv.hits.join(",")} ` +
        `marker=${existsSync(marker)} err=${err && err.message}`,
      );
    }
    assert.deepEqual(readFileSync(launcher), before);
  } finally {
    await f.close();
    srv.server.close();
    rmSync(marker, { force: true });
  }
});

test("symlink launcher is not followed", async () => {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error(`linux cache path is not the one start() uses here: ${process.platform}/${process.arch}`);
  }
  await expectRefusedStart({ channel: "stable", plat: "linux-x64", link: true });
});

test("launcher replaced after a verified download is not executed", async () => {
  resetCache();
  const plat = "linux-x64";
  const channel = "stable";
  const tag = CHANNELS[channel].tag;
  const dir = mkdtempSync(join(tmpdir(), "fortress-node-replac-"));
  const verified = join(dir, "verified");
  const planted = join(dir, "planted");
  const good = markerScript(verified, "verified");
  const evil = markerScript(planted, "planted");
  const archive = archiveFor(plat, good, dir);
  const digest = createHash("sha256").update(archive).digest("hex");
  const gets = new Map([
    ["SHA256SUMS", Buffer.from(`${digest}  ${ASSETS[plat].asset}\n`)],
    [ASSETS[plat].asset, archive],
  ]);
  const srv = await listen(gets, new Set([ASSETS[plat].asset]));
  process.env.FORTRESS_DOWNLOAD_HOST = srv.host;
  const f = new Fortress({ port: 29333, channel, headless: true });
  try {
    await f._startNative(plat);
    await new Promise((r) => setTimeout(r, 300));
    if (!existsSync(verified)) {
      throw new Error(`setup download did not produce the published launcher; hits=${srv.hits.join(",")}`);
    }
    rmSync(verified);
    if (f.proc) {
      f.proc.removeAllListeners("error");
      f.proc = null;
    }
    const launcher = launcherPath(tag, plat);
    writeFileSync(launcher, evil);
    chmodSync(launcher, 0o755);
    const tampered = readFileSync(launcher);
    let err = null;
    try {
      await f._startNative(plat);
    } catch (e) {
      err = e;
    }
    await new Promise((r) => setTimeout(r, 300));
    if (existsSync(planted) || existsSync(verified) || err === null) {
      throw new Error(
        "a launcher replaced after a verified download was started; " +
        `planted=${existsSync(planted)} verified=${existsSync(verified)} err=${err && err.message}`,
      );
    }
    assert.deepEqual(readFileSync(launcher), tampered);
  } finally {
    await f.close();
    srv.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verified launcher is not reread from the cache", async () => {
  resetCache();
  const plat = "linux-x64";
  const channel = "stable";
  const tag = CHANNELS[channel].tag;
  const dir = mkdtempSync(join(tmpdir(), "fortress-node-race-"));
  const verified = join(dir, "verified");
  const planted = join(dir, "planted");
  const good = markerScript(verified, "verified");
  const evil = markerScript(planted, "planted");
  const archive = archiveFor(plat, good, dir);
  const digest = createHash("sha256").update(archive).digest("hex");
  const gets = new Map([
    ["SHA256SUMS", Buffer.from(`${digest}  ${ASSETS[plat].asset}\n`)],
    [ASSETS[plat].asset, archive],
  ]);
  const srv = await listen(gets, new Set([ASSETS[plat].asset]));
  process.env.FORTRESS_DOWNLOAD_HOST = srv.host;
  const launcher = plant(tag, plat, good);
  writeFileSync(join(cacheRoot, tag, plat, ASSETS[plat].asset), archive);
  const cacheExecs = [];
  race.fn = (file) => {
    if (typeof file === "string" && underCache(file) && existsSync(file)) {
      cacheExecs.push(file);
      writeFileSync(file, evil);
      chmodSync(file, 0o755);
    }
  };
  const f = new Fortress({ port: 29444, channel, headless: true });
  let err = null;
  try {
    await f._startNative(plat);
    await new Promise((r) => setTimeout(r, 400));
  } catch (e) {
    err = e;
  } finally {
    race.fn = null;
    await f.close();
    srv.server.close();
  }
  if (cacheExecs.length || existsSync(planted) || !existsSync(verified)) {
    throw new Error(
      "cached launcher path was reusable after verification; " +
      `cacheExecs=${cacheExecs.join(",")} planted=${existsSync(planted)} ` +
      `verified=${existsSync(verified)} err=${err && err.message} ` +
      `launcherNow=${existsSync(launcher) ? readFileSync(launcher, "utf8") : ""}`,
    );
  }
  rmSync(dir, { recursive: true, force: true });
});

test("windows launcher is not reread from the cache", async () => {
  resetCache();
  const plat = "win-x64";
  const channel = "stable";
  const tag = CHANNELS[channel].tag;
  const dir = mkdtempSync(join(tmpdir(), "fortress-node-winrace-"));
  const verified = join(dir, "verified");
  const planted = join(dir, "planted");
  const good = markerScript(verified, "verified");
  const evil = markerScript(planted, "planted");
  const archive = archiveFor(plat, good, dir);
  const digest = createHash("sha256").update(archive).digest("hex");
  const gets = new Map([
    ["SHA256SUMS", Buffer.from(`${digest}  ${ASSETS[plat].asset}\n`)],
    [ASSETS[plat].asset, archive],
  ]);
  const srv = await listen(gets, new Set([ASSETS[plat].asset]));
  process.env.FORTRESS_DOWNLOAD_HOST = srv.host;
  plant(tag, plat, good);
  writeFileSync(join(cacheRoot, tag, plat, ASSETS[plat].asset), archive);
  const cacheExecs = [];
  race.fn = (file) => {
    if (typeof file === "string" && underCache(file) && existsSync(file)) {
      cacheExecs.push(file);
      writeFileSync(file, evil);
      chmodSync(file, 0o755);
    }
  };
  const f = new Fortress({ port: 29555, channel, headless: true });
  let err = null;
  try {
    await f._startNative(plat);
    await new Promise((r) => setTimeout(r, 400));
  } catch (e) {
    err = e;
  } finally {
    race.fn = null;
    await f.close();
    srv.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
  // On Linux, shell:true runs the .cmd path through /bin/sh, so a cache hit
  // both records the path and writes the planted marker. A private copy outside
  // the cache would write the verified marker instead.
  if (cacheExecs.length || existsSync(planted) || !existsSync(verified)) {
    throw new Error(
      "Windows launcher path inside the cache was spawned after it could be replaced; " +
      `cacheExecs=${cacheExecs.join(",")} planted=${existsSync(planted)} ` +
      `verified=${existsSync(verified)} err=${err && err.message}`,
    );
  }
});

function childEnv(extra) {
  return {
    ...process.env,
    FORTRESS_DOWNLOAD_HOST: extra.host,
    FORTRESS_CHANNEL: "stable",
    ...extra.overrides,
  };
}

test("default home cache preseed is not executed", async () => {
  const home = mkdtempSync(join(tmpdir(), "fortress-node-home-"));
  const marker = join(home, "marker");
  const tag = CHANNELS.stable.tag;
  const asset = ASSETS["linux-x64"].asset;
  const launcher = join(home, ".cache", "tilion-fortress", tag, "linux-x64", ASSETS["linux-x64"].launcher);
  mkdirSync(join(launcher, ".."), { recursive: true });
  writeFileSync(launcher, cdpScript(marker));
  chmodSync(launcher, 0o755);
  const gets = new Map([["SHA256SUMS", mismatchSums(asset)]]);
  const srv = await listen(gets, new Set([asset]));
  const env = childEnv({
    host: srv.host,
    overrides: { HOME: home },
  });
  delete env.FORTRESS_BROWSERS_PATH;
  const child = spawn(process.execPath, ["--input-type=module", "-e", `
    const { Fortress } = await import(${JSON.stringify(join(sdkNode, "index.js"))});
    const fs = await import("node:fs");
    const f = new Fortress({ port: ${30000 + (process.pid % 1000)}, channel: "stable", headless: true });
    try { await f.start(); console.log("START_OK"); }
    catch (e) { console.log("START_ERR " + e.message); }
    finally { await f.close(); }
    console.log("MARKER " + (fs.existsSync(${JSON.stringify(marker)}) ? "1" : "0"));
  `], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  child.stdout.on("data", (b) => { stdout += b; });
  let stderr = "";
  child.stderr.on("data", (b) => { stderr += b; });
  const timer = setTimeout(() => child.kill("SIGKILL"), 15000);
  const [code] = await once(child, "exit");
  clearTimeout(timer);
  srv.server.close();
  rmSync(home, { recursive: true, force: true });
  if (stdout.includes("START_OK") || stdout.includes("MARKER 1")) {
    throw new Error(`default home cache launcher was executed; stdout=${stdout} stderr=${stderr} code=${code}`);
  }
  assert.match(stdout, /START_ERR/);
  assert.match(stdout, /MARKER 0/);
});

test("cli does not execute a preseeded launcher", async () => {
  const dir = mkdtempSync(join(tmpdir(), "fortress-node-cli-"));
  const marker = join(dir, "marker");
  const cache = join(dir, "browsers");
  const tag = CHANNELS.stable.tag;
  const asset = ASSETS["linux-x64"].asset;
  const launcher = join(cache, tag, "linux-x64", ASSETS["linux-x64"].launcher);
  mkdirSync(join(launcher, ".."), { recursive: true });
  writeFileSync(launcher, cdpScript(marker));
  chmodSync(launcher, 0o755);
  const gets = new Map([["SHA256SUMS", mismatchSums(asset)]]);
  const srv = await listen(gets, new Set([asset]));
  const port = 31000 + (process.pid % 1000);
  const child = spawn(process.execPath, [join(sdkNode, "cli.js"), "--port", String(port)], {
    env: {
      ...process.env,
      FORTRESS_BROWSERS_PATH: cache,
      FORTRESS_DOWNLOAD_HOST: srv.host,
      FORTRESS_CHANNEL: "stable",
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  let settled = false;
  const done = new Promise((resolveDone) => {
    const timer = setInterval(() => {
      if (existsSync(marker)) {
        clearInterval(timer);
        settled = true;
        resolveDone("executed");
      } else if (child.exitCode !== null || child.signalCode !== null) {
        clearInterval(timer);
        settled = true;
        resolveDone("exited");
      }
    }, 30);
    setTimeout(() => {
      if (!settled) {
        clearInterval(timer);
        resolveDone("timeout");
      }
    }, 5000);
  });
  const result = await done;
  try {
    if (result === "executed" || existsSync(marker)) {
      throw new Error(`tilion-fortress CLI executed the planted launcher; hits=${srv.hits.join(",")}`);
    }
    if (result !== "exited" || child.exitCode === 0 || child.exitCode === null) {
      throw new Error(`CLI did not refuse the planted launcher (${result}, code=${child.exitCode})`);
    }
  } finally {
    try { process.kill(-child.pid, "SIGKILL"); } catch { child.kill("SIGKILL"); }
    srv.server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
