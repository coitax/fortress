// tilion-fortress (Node) — install & drive the Fortress stealth Chromium engine.
// Ships the prebuilt binary only (no engine source). Detects platform, downloads the
// matching bundle from the GitHub Release, verifies SHA256, caches it, launches with CDP.
// Every launch re-verifies the cached archive and runs a private copy extracted from the
// verified bytes, never the files in the cache.
// macOS/Windows fall back to the Docker image until native binaries are published.
import { spawn, spawnSync } from "node:child_process";
import {
  createWriteStream, existsSync, chmodSync, mkdirSync, createReadStream, copyFileSync, lstatSync,
  mkdtempSync, readdirSync, renameSync, rmSync, constants as fsConstants,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { basename, join } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createHash } from "node:crypto";

export const VERSION = "151.0.7908.0";
const REPO = "tiliondev/fortress";
// Two release channels. "stable" = Chromium 149 (recommended default — matches the Chrome version
// the mass of real users run). "latest" = 151 (newest engine). Override with { channel } or the
// FORTRESS_CHANNEL env var.
export const CHANNELS = {
  stable: { tag: "v149.0.7827.232", docker: "tilion/fortress:149.0.7827.232" },
  latest: { tag: "v151.0.7908.0",   docker: "tilion/fortress:151.0.7908.0" },
};
const DEFAULT_CHANNEL = process.env.FORTRESS_CHANNEL || "stable";
const CACHE = process.env.FORTRESS_BROWSERS_PATH || join(homedir(), ".cache", "tilion-fortress");
const hostFor = (tag) => process.env.FORTRESS_DOWNLOAD_HOST || `https://github.com/${REPO}/releases/download/${tag}`;

// platform key -> { asset, kind, launcher }
export const ASSETS = {
  "linux-x64": { asset: "tilion-fortress-linux-x64.tar.gz", kind: "tar", launcher: "tilion-fortress/tilion" },
  "win-x64":   { asset: "tilion-fortress-win-x64.zip",       kind: "zip", launcher: "tilion-fortress/tilion.cmd" },
  "mac-arm64": { asset: "tilion-fortress-mac-arm64.tar.gz",  kind: "tar", launcher: "tilion-fortress/tilion" },
  "mac-x64":   { asset: "tilion-fortress-mac-x64.tar.gz",    kind: "tar", launcher: "tilion-fortress/tilion" },
};

export function resolvePlatform() {
  const { platform, arch } = process;
  if (platform === "linux" && arch === "x64") return "linux-x64";
  if (platform === "win32" && arch === "x64") return "win-x64";
  if (platform === "darwin") return arch === "arm64" ? "mac-arm64" : "mac-x64";
  return null;
}

export function personaArgs(persona) {
  if (!persona) return [];
  const map = { platform: "--uxr-platform", timezone: "--uxr-timezone", languages: "--uxr-languages",
    webglRenderer: "--uxr-webgl-renderer", webglVendor: "--uxr-webgl-vendor",
    hwConcurrency: "--uxr-hw-concurrency", deviceMemory: "--uxr-device-memory",
    screenWidth: "--uxr-screen-width", screenHeight: "--uxr-screen-height", canvasSeed: "--uxr-canvas-seed" };
  return Object.entries(persona).map(([k, v]) => `${map[k] || `--uxr-${k}`}=${v}`);
}

export async function sha256(path) {
  const h = createHash("sha256");
  await pipeline(createReadStream(path), h);
  return h.digest("hex");
}

export async function expectedSha(asset, host) {
  try {
    const r = await fetch(`${host}/SHA256SUMS`);
    if (!r.ok) return null;
    for (const line of (await r.text()).split("\n")) {
      const p = line.trim().split(/\s+/);
      if (p.length === 2 && p[1].replace(/^\*/, "") === asset) return p[0].toLowerCase();
    }
  } catch { /* none */ }
  return null;
}

async function copyHashed(src, dst) {
  const h = createHash("sha256");
  const tap = new Transform({ transform(chunk, _enc, cb) { h.update(chunk); cb(null, chunk); } });
  await pipeline(createReadStream(src), tap, createWriteStream(dst, { flags: "wx" }));
  return h.digest("hex");
}

// Writes the release archive for `plat` to `dest`, verified against SHA256SUMS; returns true when
// it was downloaded rather than taken from the cache. The cache may be shared or writable by
// others, so `dest` must be in a directory only we can write, and only that copy is trusted.
async function fetchArchive(plat, host, tag, dest) {
  const { asset } = ASSETS[plat];
  const exp = await expectedSha(asset, host);
  if (!exp) throw new Error(`no SHA256SUMS entry for ${asset} at ${host}; refusing to use an unverified bundle`);
  try {
    if (await copyHashed(join(CACHE, tag, plat, asset), dest) === exp) return false;
  } catch { /* not cached */ }
  rmSync(dest, { force: true });
  process.stderr.write(`[tilion-fortress] downloading ${host}/${asset} ...\n`);
  const res = await fetch(`${host}/${asset}`);
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  await pipeline(res.body, createWriteStream(dest, { flags: "wx" }));
  const act = await sha256(dest);
  if (act !== exp) {
    rmSync(dest, { force: true });
    throw new Error(`SHA256 mismatch for ${asset}: expected ${exp}, got ${act}`);
  }
  process.stderr.write("[tilion-fortress] SHA256 verified\n");
  return true;
}

function extract(archive, kind, dest) {
  mkdirSync(dest, { recursive: true });
  let r;
  if (kind === "tar") {
    r = spawnSync("tar", ["xzf", archive, "-C", dest], { stdio: "inherit" });
  } else if (process.platform === "win32") {
    r = spawnSync("powershell", ["-NoProfile", "-Command",
      "Expand-Archive -Force -LiteralPath $env:TF_ARCHIVE -DestinationPath $env:TF_DEST"],
      { stdio: "inherit", env: { ...process.env, TF_ARCHIVE: archive, TF_DEST: dest } });
  } else {
    r = spawnSync("unzip", ["-q", "-o", archive, "-d", dest], { stdio: "inherit" });
  }
  if (r.status !== 0) throw new Error(`${kind} extraction failed`);
}

// Replaces the cached archive and bundle tree under `root` with the verified `archive`.
function installCache(archive, kind, root) {
  mkdirSync(root, { recursive: true });
  const stage = mkdtempSync(join(root, ".extract-"));
  try {
    extract(archive, kind, stage);
    for (const name of readdirSync(stage)) {
      const dest = join(root, name);
      rmSync(dest, { recursive: true, force: true });
      renameSync(join(stage, name), dest);
    }
    const copy = join(stage, basename(archive));
    copyFileSync(archive, copy, fsConstants.COPYFILE_EXCL);
    renameSync(copy, join(root, basename(archive)));
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
}

// Extracts the verified bundle into a new private directory and returns { dir, launcherPath }.
// Nothing in the cache is executed. Refuses to start when the cached launcher is not the one in
// the verified release.
async function privateBundle(plat, host, tag) {
  const { asset, kind, launcher } = ASSETS[plat];
  const root = join(CACHE, tag, plat);   // cache per release tag so channels don't collide
  const dir = mkdtempSync(join(tmpdir(), "tilion-fortress-"));
  try {
    const archive = join(dir, asset);
    if (await fetchArchive(plat, host, tag, archive)) installCache(archive, kind, root);
    const bundle = join(dir, "bundle");
    extract(archive, kind, bundle);
    rmSync(archive);
    const launcherPath = join(bundle, launcher);
    if (!existsSync(launcherPath)) throw new Error(`launcher missing after extract: ${launcherPath}`);
    if (!launcher.endsWith(".cmd")) chmodSync(launcherPath, 0o755);
    const cached = join(root, launcher);
    let st = null;
    try { st = lstatSync(cached); } catch { /* no cached tree */ }
    if (st && (!st.isFile() || await sha256(cached) !== await sha256(launcherPath)))
      throw new Error(`cached launcher ${cached} does not match the verified release; refusing to start. Delete ${root} to reinstall.`);
    return { dir, launcherPath };
  } catch (e) {
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
}

async function assetExists(plat, host) {
  try { return (await fetch(`${host}/${ASSETS[plat].asset}`, { method: "HEAD" })).ok; }
  catch { return false; }
}

async function waitCdp(port, timeoutMs = 90000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { const r = await fetch(`http://127.0.0.1:${port}/json/version`); if (r.ok) return (await r.json()).webSocketDebuggerUrl; }
    catch {}
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("Fortress CDP endpoint did not come up");
}

export class Fortress {
  constructor({ port = 9222, persona = null, extraArgs = [], headless = true, channel = DEFAULT_CHANNEL } = {}) {
    if (!CHANNELS[channel]) throw new Error(`unknown channel '${channel}'; use one of ${Object.keys(CHANNELS)}`);
    const { tag, docker } = CHANNELS[channel];
    Object.assign(this, { port, persona, extraArgs, headless, channel, tag, docker, host: hostFor(tag),
                          proc: null, dockerName: null, bundleDir: null, cdpUrl: null });
  }
  static async launch(opts) { return new Fortress(opts).start(); }

  async start() {
    const plat = resolvePlatform();
    const native = plat && (plat === "linux-x64" || await assetExists(plat, this.host));
    if (native) await this._startNative(plat); else this._startDocker();
    this.cdpUrl = await waitCdp(this.port);
    return this;
  }

  async _startNative(plat) {
    const { dir, launcherPath } = await privateBundle(plat, this.host, this.tag);
    const args = [];
    if (this.headless) args.push("--headless=new", "--no-sandbox");
    args.push(`--remote-debugging-port=${this.port}`, `--user-data-dir=${join(CACHE, "profile")}`,
              ...personaArgs(this.persona), ...this.extraArgs);
    try {
      this.proc = spawn(launcherPath, args, { stdio: "ignore", shell: launcherPath.endsWith(".cmd") });
    } catch (e) {
      rmSync(dir, { recursive: true, force: true });
      throw e;
    }
    this.bundleDir = dir;
  }

  _startDocker() {
    if (spawnSync("docker", ["--version"]).status !== 0)
      throw new Error("No native binary for this platform yet and Docker not installed. Install Docker Desktop or use Linux x64.");
    this.dockerName = `tilion-fortress-${process.pid}-${this.port}`;
    const args = ["run", "-d", "--rm", "--name", this.dockerName, "-p", `${this.port}:9222`, this.docker,
      ...personaArgs(this.persona), ...this.extraArgs];
    if (spawnSync("docker", args, { stdio: "ignore" }).status !== 0) throw new Error("docker run failed");
  }

  async close() {
    if (this.proc) {
      // On Windows the launcher runs under cmd.exe (shell:true); proc.kill() would
      // only reap the shell and orphan chrome.exe, so kill the whole process tree.
      if (process.platform === "win32" && this.proc.pid)
        spawnSync("taskkill", ["/F", "/T", "/PID", String(this.proc.pid)], { stdio: "ignore" });
      else this.proc.kill();
      this.proc = null;
    }
    if (this.bundleDir) {
      try { rmSync(this.bundleDir, { recursive: true, force: true, maxRetries: 5 }); } catch { /* still in use */ }
      this.bundleDir = null;
    }
    if (this.dockerName) { spawnSync("docker", ["rm", "-f", this.dockerName], { stdio: "ignore" }); this.dockerName = null; }
  }
}
export default Fortress;
