#!/usr/bin/env node
"use strict";

const cp = require("child_process");
const fs = require("fs");
const path = require("path");

function buildTool() {
    const binDir = __dirname;
    const src = path.join(binDir, "epass2003-tool.c");
    const out = path.join(binDir, "epass2003-tool");
    const incLocal = path.join(binDir, "include");

    if (!fs.existsSync(src)) {
        console.error(`[-] Source file not found: ${src}`);
        return false;
    }

    const includeDirs = [
        incLocal,
        "/opt/homebrew/include",
        "/usr/local/include",
        "/usr/include"
    ].filter(d => fs.existsSync(d));

    const libDirs = [
        "/opt/homebrew/lib",
        "/usr/local/lib",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu"
    ].filter(d => fs.existsSync(d));

    const compilers = ["clang", "gcc", "cc"];
    let lastError = null;

    for (const compiler of compilers) {
        try {
            const args = [
                "-O2",
                ...includeDirs.map(d => `-I${d}`),
                ...libDirs.map(d => `-L${d}`),
                src,
                "-o",
                out,
                "-lopensc"
            ];

            const result = cp.spawnSync(compiler, args, { stdio: "pipe" });
            if (result.status === 0 && fs.existsSync(out)) {
                fs.chmodSync(out, 0o755);
                console.log(`[✔] Built ${out} successfully using ${compiler}`);
                return true;
            }
            if (result.stderr && result.stderr.length > 0) {
                lastError = result.stderr.toString();
            }
        } catch (e) {
            lastError = e.message;
        }
    }

    console.error(`[-] Failed to build epass2003-tool.`);
    if (lastError) console.error(`[-] Error details: ${lastError.trim()}`);
    console.error(`[-] Please ensure 'opensc' is installed:`);
    console.error(`    macOS: brew install opensc`);
    console.error(`    Ubuntu/Debian: sudo apt install libopensc-dev opensc`);
    console.error(`    Arch: sudo pacman -S opensc`);
    console.error(`    Fedora: sudo dnf install opensc-devel`);
    return false;
}

if (require.main === module) {
    const ok = buildTool();
    process.exit(ok ? 0 : 1);
}

module.exports = { buildTool };
