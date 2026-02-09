"use strict";

const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const os = require("os");

const REPO = "VikingOwl91/mcp-firewall";

const PLATFORM_MAP = {
  linux: "Linux",
  darwin: "Darwin",
  win32: "Windows",
};

const ARCH_MAP = {
  x64: "x86_64",
  arm64: "arm64",
};

function getVersion() {
  const pkg = JSON.parse(
    fs.readFileSync(path.join(__dirname, "package.json"), "utf8")
  );
  return pkg.version;
}

function getArtifactName(platform, arch) {
  const os = PLATFORM_MAP[platform];
  const cpu = ARCH_MAP[arch];
  if (!os || !cpu) {
    throw new Error(`Unsupported platform: ${platform}-${arch}`);
  }
  const ext = platform === "win32" ? "zip" : "tar.gz";
  return `mcp-firewall_${os}_${cpu}.${ext}`;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const get = (url, redirects) => {
      if (redirects > 5) {
        reject(new Error("Too many redirects"));
        return;
      }
      https
        .get(url, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            get(res.headers.location, redirects + 1);
            return;
          }
          if (res.statusCode !== 200) {
            reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
            return;
          }
          const chunks = [];
          res.on("data", (chunk) => chunks.push(chunk));
          res.on("end", () => resolve(Buffer.concat(chunks)));
          res.on("error", reject);
        })
        .on("error", reject);
    };
    get(url, 0);
  });
}

function extractTarGz(buffer, destDir) {
  const tmpFile = path.join(os.tmpdir(), `mcp-firewall-${Date.now()}.tar.gz`);
  fs.writeFileSync(tmpFile, buffer);
  fs.mkdirSync(destDir, { recursive: true });
  try {
    execSync(`tar xzf "${tmpFile}" -C "${destDir}"`, { stdio: "ignore" });
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

function extractZip(buffer, destDir) {
  const tmpFile = path.join(os.tmpdir(), `mcp-firewall-${Date.now()}.zip`);
  fs.writeFileSync(tmpFile, buffer);
  fs.mkdirSync(destDir, { recursive: true });
  try {
    // PowerShell available on all modern Windows
    execSync(
      `powershell -Command "Expand-Archive -Force '${tmpFile}' '${destDir}'"`,
      { stdio: "ignore" }
    );
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function main() {
  const version = getVersion();
  if (version === "0.0.0") {
    console.log("Skipping binary download for development version (0.0.0).");
    return;
  }

  const platform = process.platform;
  const arch = process.arch;

  const artifact = getArtifactName(platform, arch);
  const url = `https://github.com/${REPO}/releases/download/v${version}/${artifact}`;
  const binDir = path.join(__dirname, "bin");

  console.log(`Downloading mcp-firewall v${version} for ${platform}-${arch}...`);

  const buffer = await download(url);

  if (artifact.endsWith(".zip")) {
    extractZip(buffer, binDir);
  } else {
    extractTarGz(buffer, binDir);
  }

  // Make binary executable on Unix
  if (platform !== "win32") {
    const binaryPath = path.join(binDir, "mcp-firewall");
    fs.chmodSync(binaryPath, 0o755);
  }

  console.log("mcp-firewall installed successfully.");
}

main().catch((err) => {
  console.error(`Failed to install mcp-firewall: ${err.message}`);
  process.exit(1);
});
