#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const graphene = require("graphene-pk11");
const forge = require("node-forge");
const xmlcrypto = require("xml-crypto");
const dom = require("xmldom").DOMParser;
const DOM = new dom();

// Parse CLI arguments
const args = process.argv.slice(2);
if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
    console.log(`
Usage:
  node cli-sign.js <file-to-sign> [options]

Options:
  --pin <pin>       Token PIN (default: from config.json or TOKEN_PIN env)
  --out <outfile>   Output file path (default: <filename>.signed.ext or <filename>.p7s)
  --module <path>   Path to PKCS#11 shared library (.so)

Examples:
  node cli-sign.js document.pdf
  node cli-sign.js invoice.xml --pin 12345678
    `);
    process.exit(0);
}

const targetFile = args[0];
if (!fs.existsSync(targetFile)) {
    console.error(`Error: File not found: ${targetFile}`);
    process.exit(1);
}

// Load config
let config = {
    pin: process.env.TOKEN_PIN || "",
    pkcs11Path: "/usr/lib/opensc-pkcs11.so"
};

const configPath = path.join(__dirname, "config.json");
if (fs.existsSync(configPath)) {
    try {
        config = { ...config, ...JSON.parse(fs.readFileSync(configPath, "utf8")) };
    } catch (e) {}
}

const pinIdx = args.indexOf("--pin");
if (pinIdx !== -1 && args[pinIdx + 1]) config.pin = args[pinIdx + 1];

const moduleIdx = args.indexOf("--module");
if (moduleIdx !== -1 && args[moduleIdx + 1]) config.pkcs11Path = args[moduleIdx + 1];

const outIdx = args.indexOf("--out");
let outFile = outIdx !== -1 && args[outIdx + 1] ? args[outIdx + 1] : null;

// Determine module path
const candidates = [
    config.pkcs11Path,
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib/pkcs11/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "C:/Windows/SysWOW64/fptca_v4.dll",
    "C:/Windows/System32/fptca_v4.dll"
];

let selectedModule = null;
for (const p of candidates) {
    if (p && fs.existsSync(p)) {
        selectedModule = p;
        break;
    }
}

if (!selectedModule) {
    selectedModule = config.pkcs11Path;
}

console.log(`[+] Target file: ${targetFile}`);
console.log(`[+] PKCS#11 Module: ${selectedModule}`);

try {
    const mod = graphene.Module.load(selectedModule);
    mod.initialize();

    const slots = mod.getSlots(true);
    if (slots.length === 0) {
        console.error("[-] No token found in any slot. Please insert your USB token.");
        process.exit(1);
    }

    const slot = slots.items(0);
    console.log(`[+] Token detected: ${slot.description}`);

    const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);
    session.login(config.pin);
    console.log(`[+] PIN login successful!`);

    const certs = session.find({ class: graphene.ObjectClass.CERTIFICATE });
    const keys = session.find({ class: graphene.ObjectClass.PRIVATE_KEY });

    if (certs.length === 0 || keys.length === 0) {
        console.error("[-] No certificates or private keys found on token.");
        process.exit(1);
    }

    const cert = certs.items(0).toType();
    const certificate = forge.pki.certificateFromAsn1(forge.asn1.fromDer(cert.value.toString("binary")));
    const privateKey = keys.items(0).toType();

    console.log(`[+] Signer Subject: ${certificate.subject.getField("CN").value}`);
    console.log(`[+] Signer Serial:  ${certificate.serialNumber}`);

    const ext = path.extname(targetFile).toLowerCase();
    const fileBytes = fs.readFileSync(targetFile);

    if (ext === ".pdf") {
        if (!outFile) outFile = targetFile.replace(/\.pdf$/i, ".signed.p7s");
        console.log(`[+] Signing PDF (PKCS#7 detached signature)...`);

        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(fileBytes.toString("binary"));
        p7.addCertificate(certificate);

        const signer = {
            sign: (md, algo) => {
                const sign = session.createSign("SHA256_RSA_PKCS", privateKey);
                return sign.once(fileBytes).toString("binary");
            }
        };

        p7.addSigner({
            key: signer,
            certificate: certificate,
            digestAlgorithm: forge.pki.oids.sha256
        });
        p7.sign({ detached: true });

        const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
        fs.writeFileSync(outFile, Buffer.from(raw, "binary"));
        console.log(`[✔] Signature successfully created at: ${outFile}`);
    } else if (ext === ".xml") {
        if (!outFile) outFile = targetFile.replace(/\.xml$/i, ".signed.xml");
        console.log(`[+] Signing XML document...`);

        const xmlString = fileBytes.toString("utf8");
        const doc = DOM.parseFromString(xmlString);
        const sig = new xmlcrypto.SignedXml();
        sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        sig.addReference("//*[local-name(.)='Object']", null, "http://www.w3.org/2001/04/xmlenc#sha256");

        const pem = cert.value.toString("base64").match(/.{1,64}/g).join("\n");
        const certPem = `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----`;

        sig.keyInfoProvider = {
            getKeyInfo: () => `<X509Data><X509Certificate>${cert.value.toString("base64")}</X509Certificate></X509Data>`,
            getKey: () => certPem
        };

        const signedInfo = sig.createSignedInfo(doc);
        const signedInfoXml = signedInfo.replace("<SignedInfo>", "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
        const dummy = DOM.parseFromString(`<dummy>${signedInfoXml}</dummy>`);
        const canonXml = sig.getCanonXml(["http://www.w3.org/2001/10/xml-exc-c14n#"], dummy.documentElement.firstChild);

        const sign = session.createSign("SHA256_RSA_PKCS", privateKey);
        sign.update(canonXml);
        const signedVal = sign.final().toString("base64");

        const signXml = `<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">${signedInfo}<SignatureValue>${signedVal}</SignatureValue><KeyInfo><X509Data><X509Certificate>${cert.value.toString("base64")}</X509Certificate></X509Data></KeyInfo></Signature>`;
        const signDoc = DOM.parseFromString(`<dummy>${signXml}</dummy>`);
        doc.documentElement.appendChild(signDoc.documentElement.firstChild);

        fs.writeFileSync(outFile, doc.toString(), "utf8");
        console.log(`[✔] Signed XML successfully written to: ${outFile}`);
    } else {
        console.warn(`[!] Unknown file type '${ext}', signing as binary file to PKCS#7...`);
        if (!outFile) outFile = targetFile + ".p7s";
        // fallback to PKCS#7
        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(fileBytes.toString("binary"));
        p7.addCertificate(certificate);
        const signer = {
            sign: () => {
                const sign = session.createSign("SHA256_RSA_PKCS", privateKey);
                return sign.once(fileBytes).toString("binary");
            }
        };
        p7.addSigner({ key: signer, certificate: certificate, digestAlgorithm: forge.pki.oids.sha256 });
        p7.sign({ detached: true });
        const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
        fs.writeFileSync(outFile, Buffer.from(raw, "binary"));
        console.log(`[✔] Signature written to: ${outFile}`);
    }

    session.logout();
    session.close();
    mod.finalize();
    mod.close();
    console.log(`[✔] Done!`);
} catch (e) {
    console.error(`[-] Signing failed: ${e.message}`);
    process.exit(1);
}
