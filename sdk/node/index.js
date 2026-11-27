// tilion-fortress (Node) — install & drive the Fortress stealth Chromium engine.
// Ships the prebuilt binary only (no engine source). Detects platform, downloads the
// matching bundle from the GitHub Release, verifies SHA256, caches it, launches with CDP.
// macOS/Windows fall back to the Docker image until native binaries are published.
import { spawn, spawnSync } from "node:child_process";
import { createWriteStream, existsSync, chmodSync, mkdirSync, createReadStream } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
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

// Mirrors packaging/tilion.cmd. On Windows the SDK starts chrome.exe directly instead of
// that launcher: a .cmd file can only run under cmd.exe, which would parse persona values
// and extraArgs as shell syntax. Keep the flags and their order in sync with tilion.cmd.
export const WIN_DEFAULT_ARGS = [
  "--uxr-platform=Win32", "--uxr-ua-platform=Windows", "--uxr-ua-os=Windows NT 10.0; Win64; x64",
  "--uxr-ua-arch=x86", "--uxr-ua-bitness=64", "--uxr-ua-platform-version=15.0.0", "--uxr-ua-brand=Google Chrome",
  "--uxr-hw-concurrency=16", "--uxr-device-memory=8",
  "--uxr-webgl-vendor=Google Inc. (NVIDIA)",
  "--uxr-webgl-renderer=ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
  "--uxr-webgl-fullparams=1", "--uxr-canvas-seed=778899", "--uxr-audio-seed=445566",
  "--uxr-timezone=America/New_York", "--uxr-languages=en-US,en", "--accept-lang=en-US,en",
  "--uxr-screen-width=1920", "--uxr-screen-height=1080",
  "--uxr-webrtc-policy=disable_non_proxied_udp",
  "--enable-unsafe-webgpu", "--enable-features=Vulkan", "--use-webgpu-adapter=swiftshader",
  "--enable-dawn-features=use_vulkan", "--uxr-webgpu-vendor=nvidia", "--uxr-webgpu-architecture=ampere",
  "--uxr-webgpu-description=NVIDIA GeForce RTX 3060",
];

export function windowsLaunch(launcherPath, args, env = process.env) {
  const here = dirname(launcherPath);
  const exe = join(here, "chrome.exe");
  if (!existsSync(exe)) throw new Error(`chrome.exe missing from bundle: ${exe}`);
  return {
    command: exe,
    args: ["--use-angle=swiftshader", ...(env.TILION_NO_DEFAULTS ? [] : WIN_DEFAULT_ARGS), ...args],
    env: { ...env, VK_ICD_FILENAMES: join(here, "vk_swiftshader_icd.json") },
  };
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

async function ensureNative(plat, host, tag) {
  const { asset, kind, launcher } = ASSETS[plat];
  const root = join(CACHE, tag, plat);   // cache per release tag so channels don't collide
  const launcherPath = join(root, launcher);
  if (existsSync(launcherPath)) return launcherPath;
  mkdirSync(root, { recursive: true });
  const archive = join(root, asset);
  process.stderr.write(`[tilion-fortress] downloading ${host}/${asset} ...\n`);
  const res = await fetch(`${host}/${asset}`);
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  await pipeline(res.body, createWriteStream(archive));

  const exp = await expectedSha(asset, host);
  if (exp) {
    const act = await sha256(archive);
    if (act !== exp) throw new Error(`SHA256 mismatch for ${asset}: expected ${exp}, got ${act}`);
    process.stderr.write("[tilion-fortress] SHA256 verified\n");
  } else {
    process.stderr.write("[tilion-fortress] WARNING: no SHA256SUMS published; skipping verification\n");
  }

  if (kind === "tar") {
    if (spawnSync("tar", ["xzf", archive, "-C", root], { stdio: "inherit" }).status !== 0)
      throw new Error("tar extraction failed");
  } else { // zip (Windows): use PowerShell Expand-Archive
    // Paths go through the environment so PowerShell never parses them as script text.
    if (spawnSync("powershell", ["-NoProfile", "-NonInteractive", "-Command",
        "Expand-Archive -Force -LiteralPath $env:TILION_ZIP -DestinationPath $env:TILION_DEST"],
        { stdio: "inherit", env: { ...process.env, TILION_ZIP: archive, TILION_DEST: root } }).status !== 0)
      throw new Error("zip extraction failed");
  }
  if (!launcher.endsWith(".cmd") && existsSync(launcherPath)) chmodSync(launcherPath, 0o755);
  if (!existsSync(launcherPath)) throw new Error(`launcher missing after extract: ${launcherPath}`);
  return launcherPath;
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
                          proc: null, dockerName: null, cdpUrl: null });
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
    const launcher = await ensureNative(plat, this.host, this.tag);
    const args = [];
    if (this.headless) args.push("--headless=new", "--no-sandbox");
    args.push(`--remote-debugging-port=${this.port}`, `--user-data-dir=${join(CACHE, "profile")}`,
              ...personaArgs(this.persona), ...this.extraArgs);
    if (plat === "win-x64") {
      const { command, args: argv, env } = windowsLaunch(launcher, args);
      this.proc = spawn(command, argv, { stdio: "ignore", env });
    } else {
      this.proc = spawn(launcher, args, { stdio: "ignore" });
    }
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
      // On Windows proc.kill() only ends the browser process and orphans its
      // child processes, so kill the whole process tree.
      if (process.platform === "win32" && this.proc.pid)
        spawnSync("taskkill", ["/F", "/T", "/PID", String(this.proc.pid)], { stdio: "ignore" });
      else this.proc.kill();
      this.proc = null;
    }
    if (this.dockerName) { spawnSync("docker", ["rm", "-f", this.dockerName], { stdio: "ignore" }); this.dockerName = null; }
  }
}
export default Fortress;
