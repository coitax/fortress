// Windows launch flags must not be interpreted by cmd.exe.
//
// Fortress._startNative appends personaArgs() and extraArgs to the .cmd
// launcher and spawns it with shell:true. On win32, Node joins those
// arguments, wraps them in quotes, and runs cmd.exe /d /s /c. /s strips
// that wrapper, so a separator inside a persona value or extra argument
// becomes a second command. These tests plant a launcher, force that win32
// shell path, and interpret the command line the way cmd.exe does
// (sdk/python/tests/win_cmd.py).
//
// They fail while the injected command is dispatched. A fix passes when it
// is not, including when launch is rejected before the process is created.
// A file written by the injected command is a failure even if the SDK then
// raises.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, existsSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, delimiter } from "node:path";
import { fileURLToPath } from "node:url";

const cacheRoot = mkdtempSync(join(tmpdir(), "fortress-node-cache-"));
process.env.FORTRESS_BROWSERS_PATH = cacheRoot;
const { Fortress } = await import("../index.js");

const winCmd = fileURLToPath(new URL("../../python/tests/win_cmd.py", import.meta.url));

let chain = Promise.resolve();
function locked(fn) {
  const run = chain.then(fn, fn);
  chain = run.then(() => {}, () => {});
  return run;
}

function plantLauncher(tag) {
  const launcher = join(cacheRoot, tag, "win-x64", "tilion-fortress", "tilion.cmd");
  mkdirSync(join(launcher, ".."), { recursive: true });
  writeFileSync(launcher, "@echo off\r\n");
  return launcher;
}

function installCmd(dir) {
  const bin = join(dir, "bin");
  mkdirSync(bin, { recursive: true });
  const exe = join(bin, "cmd.exe");
  writeFileSync(exe, `#!/bin/sh\nexec python3 ${JSON.stringify(winCmd)} "$@"\n`);
  chmodSync(exe, 0o755);
  return bin;
}

async function launch(opts) {
  return locked(async () => {
    const dir = mkdtempSync(join(tmpdir(), "fortress-node-launch-"));
    const marker = join(dir, "marker");
    const bin = installCmd(dir);
    const prev = {
      platform: Object.getOwnPropertyDescriptor(process, "platform"),
      path: process.env.PATH,
      comspec: process.env.comspec,
      marker: process.env.FORTRESS_CMD_MARKER,
    };
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    process.env.PATH = `${bin}${delimiter}${process.env.PATH || ""}`;
    process.env.comspec = "cmd.exe";
    process.env.FORTRESS_CMD_MARKER = marker;
    const fort = new Fortress({ port: 9, ...opts });
    plantLauncher(fort.tag);
    let detail = "";
    let err = "";
    try {
      await fort._startNative("win-x64");
      if (fort.proc) {
        await new Promise((resolve) => {
          const timer = setTimeout(resolve, 5000);
          fort.proc.on("exit", () => { clearTimeout(timer); resolve(); });
          fort.proc.on("error", () => { clearTimeout(timer); resolve(); });
        });
      }
    } catch {
      // A rejection before spawn is a successful fix only when nothing was written.
    } finally {
      const errPath = `${marker}.err`;
      if (existsSync(errPath)) err = readFileSync(errPath, "utf8");
      if (existsSync(marker)) detail = readFileSync(marker, "utf8");
      Object.defineProperty(process, "platform", prev.platform);
      process.env.PATH = prev.path;
      if (prev.comspec === undefined) delete process.env.comspec;
      else process.env.comspec = prev.comspec;
      if (prev.marker === undefined) delete process.env.FORTRESS_CMD_MARKER;
      else process.env.FORTRESS_CMD_MARKER = prev.marker;
      rmSync(dir, { recursive: true, force: true });
    }
    if (err) throw new Error(err);
    return detail;
  });
}

function assertNotInjected(detail) {
  assert.equal(detail, "");
}

test("benign persona does not dispatch a second command", async () => {
  const marker = await launch({
    persona: { timezone: "America/New_York", webglRenderer: "ANGLE (NVIDIA, RTX 3060)" },
    extraArgs: ["--window-size=1280,800"],
  });
  assertNotInjected(marker);
});

test("persona timezone separator is not a second command", async () => {
  const marker = await launch({ persona: { timezone: "UTC&pwned" } });
  assertNotInjected(marker);
});

test("persona languages separator is not a second command", async () => {
  const marker = await launch({ persona: { languages: "en-US&pwned" } });
  assertNotInjected(marker);
});

test("persona webgl renderer separator is not a second command", async () => {
  // Spaces do not save the Node path: shell:true joins every argument, and
  // cmd.exe /s strips the single pair of quotes around that whole line.
  const marker = await launch({
    persona: { webglRenderer: "ANGLE (NVIDIA, RTX 3060) & pwned" },
  });
  assertNotInjected(marker);
});

test("persona webgl vendor separator is not a second command", async () => {
  const marker = await launch({ persona: { webglVendor: "Google Inc.&pwned" } });
  assertNotInjected(marker);
});

test("persona && separator is not a second command", async () => {
  assertNotInjected(await launch({ persona: { timezone: "UTC&&pwned" } }));
});

test("persona pipe separator is not a second command", async () => {
  assertNotInjected(await launch({ persona: { timezone: "UTC|pwned" } }));
});

test("persona output redirect is not performed", async () => {
  assertNotInjected(await launch({ persona: { timezone: "UTC>pwned.txt" } }));
});

test("persona input redirect is not performed", async () => {
  assertNotInjected(await launch({ persona: { timezone: "UTC<pwned.txt" } }));
});

test("extraArgs separator is not a second command", async () => {
  const marker = await launch({ extraArgs: ["--proxy-server=127.0.0.1&pwned"] });
  assertNotInjected(marker);
});

test("extraArgs element that is only a separator is not executed", async () => {
  const marker = await launch({ extraArgs: ["&pwned"] });
  assertNotInjected(marker);
});

test("unknown persona key shares the same command line", async () => {
  const marker = await launch({ persona: { audioSeed: "1&pwned" } });
  assertNotInjected(marker);
});
