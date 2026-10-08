"use strict";

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const moment = require("moment");
const graphene = require("graphene-pk11");
const forge = require("node-forge");
const xmlcrypto = require("xml-crypto");
const select = xmlcrypto.xpath;
const dom = require("xmldom").DOMParser;
const DOM = new dom();
const requestIP = require("request-ip");
const crypto = require("crypto");
const tokenNative = require("./token-native");
const { signXmlDocument } = require("./xml-signer");

// Load config
const configPath = path.join(__dirname, "config.json");
let config = {
    port: 35317,
    pin: process.env.TOKEN_PIN || "",
    pkcs11Path: "/usr/lib/opensc-pkcs11.so",
    fallbackPaths: [
        "/usr/lib/pkcs11/opensc-pkcs11.so",
        "/usr/lib64/opensc-pkcs11.so",
        "/usr/local/lib/opensc-pkcs11.so",
        "/usr/lib/libePass2003.so"
    ]
};

if (fs.existsSync(configPath)) {
    try {
        const loaded = JSON.parse(fs.readFileSync(configPath, "utf8"));
        config = { ...config, ...loaded };
    } catch (e) {
        console.warn("[WARN] Could not parse config.json, using defaults:", e.message);
    }
}

if (process.env.TOKEN_PIN) {
    config.pin = process.env.TOKEN_PIN;
}

const DTF = "YYYY-MM-DD HH:mm:ss";
const uploadXML = multer({ storage: multer.memoryStorage(), limits: { fileSize: 67108864 } }).single("upload");

let mod = null;
let CERTS = [];

// Helper functions for certificates
const b642pem = (b64) => {
    const pem = b64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN CERTIFICATE-----\n${pem}\n-----END CERTIFICATE-----`;
};

const _checkmst = (mst) => {
    if (!(/^[0-9]{10}$|^[0-9]{10}\-[0-9]{3}$/.test(mst))) return false;
    const ms1 = parseInt(mst.substr(0, 1));
    const ms2 = parseInt(mst.substr(1, 1));
    const ms3 = parseInt(mst.substr(2, 1));
    const ms4 = parseInt(mst.substr(3, 1));
    const ms5 = parseInt(mst.substr(4, 1));
    const ms6 = parseInt(mst.substr(5, 1));
    const ms7 = parseInt(mst.substr(6, 1));
    const ms8 = parseInt(mst.substr(7, 1));
    const ms9 = parseInt(mst.substr(8, 1));
    const ms10 = parseInt(mst.substr(9, 1));
    const a = 31 * ms1 + 29 * ms2 + 23 * ms3 + 19 * ms4 + 17 * ms5 + 13 * ms6 + 7 * ms7 + 5 * ms8 + 3 * ms9;
    return ms10 === 10 - (a % 11);
};

const _checkcccd = (cccd) => /^[0-9]{12}$/.test(cccd);
const checkmst = (...params) => _checkmst(...params) || _checkcccd(...params);

const getmst = (sub) => {
    for (const obj of sub.attributes) {
        const type = obj.type;
        if (type == "0.9.2342.19200300.100.1.1" || type == "2.5.4.10" || type == "2.5.4.3" || type == "2.5.4.8") {
            const arr = obj.value.split(":");
            let mst = arr[arr.length - 1];
            if (/^[0-9]{10}[0-9]{3}$/.test(mst)) mst = `${mst.substr(0, 10)}-${mst.substr(10)}`;
            if (checkmst(mst)) return mst;
        }
    }
    return null;
};

const getdtl = (obj) => {
    return obj.attributes.map(attr => {
        const sn = attr.shortName, regex = /^MST\:\d{10}(\-\d{3})*$/;
        let val = attr.value;
        try { val = forge.util.decodeUtf8(val); } catch (e) {}
        let bonusVal = val;
        if (regex.test(attr.value)) bonusVal = `${attr.type}${attr.value}`;
        return sn ? [sn, bonusVal].join("=") : val;
    }).join(", ");
};

const getSubjectCirculars78 = (obj) => {
    return obj.attributes.map(attr => {
        const sn = attr.shortName, regex = /^MST\:\d{10}(\-\d{3})*$/;
        let val = attr.value;
        try { val = forge.util.decodeUtf8(val); } catch (e) {}
        let bonusVal = val;
        if (regex.test(attr.value)) bonusVal = `${attr.type}${attr.value}`;
        return sn ? [sn, bonusVal].join("=") : [attr.type, val].join('=');
    }).join(", ");
};

const getCnInSubject = (obj) => {
    for (let attr of obj.attributes) {
        if (attr.shortName === "CN") {
            try { return forge.util.decodeUtf8(attr.value); } catch (e) { return attr.value; }
        }
    }
    return "";
};

const escapeHtml = (text) => {
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
    return text.replace(/[&<>"]/g, (m) => map[m] || m);
};

const x509Data = (ca) => {
    return `<X509Data><X509SubjectName>${escapeHtml(ca.subject)}</X509SubjectName><X509Certificate>${ca.c64}</X509Certificate></X509Data>`;
};

function myKeyInfo(ca) {
    this.getKeyInfo = () => x509Data(ca);
    this.getKey = () => b642pem(ca.c64);
}

// Locate PKCS#11 driver
function resolvePkcs11Module() {
    const candidates = [config.pkcs11Path, ...(config.fallbackPaths || [])];
    for (const p of candidates) {
        if (p && fs.existsSync(p)) {
            return p;
        }
    }
    return config.pkcs11Path;
}

// PKCS#11 Token Management
async function initPkcs11() {
    try {
        if (tokenNative.isAvailable()) {
            try {
                CERTS = tokenNative.init(config.pin);
                if (CERTS && CERTS.length > 0) {
                    console.log(`[TokenNative] Successfully initialized Feitian ePass2003 with ${CERTS.length} certificate(s)!`);
                    return true;
                }
            } catch (nativeErr) {
                console.warn("[TokenNative] Native driver warning:", nativeErr.message);
            }
        }

        if (mod) {
            try { mod.finalize(); mod.close(); } catch (e) {}
            mod = null;
        }

        const modulePath = resolvePkcs11Module();
        console.log(`[PKCS#11] Loading module: ${modulePath}`);
        if (!fs.existsSync(modulePath)) {
            console.error(`[PKCS#11] Module not found at ${modulePath}. Make sure 'opensc' is installed: sudo pacman -S opensc`);
        }

        mod = graphene.Module.load(modulePath);
        mod.initialize();

        const slots = mod.getSlots(true);
        if (slots.length === 0) {
            console.warn("[PKCS#11] No smartcard token present in any slot.");
            CERTS = [];
            return false;
        }

        const slot = slots.items(0);
        console.log(`[PKCS#11] Found Token in slot: ${slot.description} (Reader: ${slot.name})`);

        const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RO_SESSION);
        try {
            const certs = session.find({ class: graphene.ObjectClass.CERTIFICATE });
            console.log(`[PKCS#11] Certificates found on token: ${certs.length}`);

            CERTS = [];
            const now = moment();

            for (let i = 0; i < certs.length; i++) {
                try {
                    const certObj = certs.items(i).toType();
                    if (certObj instanceof graphene.X509Certificate) {
                        const derBuffer = certObj.value;
                        const certificate = forge.pki.certificateFromAsn1(forge.asn1.fromDer(derBuffer.toString("binary")));
                        const validity = certificate.validity;
                        const notBefore = validity.notBefore;
                        const notAfter = validity.notAfter;

                        const serial = certificate.serialNumber;
                        const subject = certificate.subject;
                        const issuer = certificate.issuer;
                        const mst = getmst(subject);
                        let scn = "";
                        try {
                            scn = subject.getField("CN").value;
                            scn = forge.util.decodeUtf8(scn);
                        } catch (e) {
                            scn = getCnInSubject(subject);
                        }

                        let icn = "";
                        try {
                            icn = issuer.getField("CN").value;
                            icn = forge.util.decodeUtf8(icn);
                        } catch (e) {
                            icn = getCnInSubject(issuer);
                        }

                        const fd = moment(notBefore);
                        const td = moment(notAfter);

                        const entry = {
                            cn: icn || scn,
                            serialNumber: serial,
                            serial: serial,
                            mst: mst,
                            subject: getSubjectCirculars78(subject),
                            issuer: getdtl(issuer),
                            notBefore: notBefore,
                            notAfter: notAfter,
                            fd: fd.format(DTF),
                            td: td.format(DTF),
                            cnInSubject: scn,
                            c64: derBuffer.toString("base64"),
                            info: `#${mst || ""}#${scn}#${fd.format("YYYY-MM-DD")}..${td.format("YYYY-MM-DD")}`,
                            certificate: certificate,
                            certId: certObj.id
                        };

                        CERTS.push(entry);
                        console.log(`[PKCS#11] Loaded Cert: ${scn} (Serial: ${serial}, Valid: ${entry.fd} -> ${entry.td})`);
                    }
                } catch (certErr) {
                    console.warn(`[PKCS#11] Error parsing cert index ${i}:`, certErr.message);
                }
            }
        } finally {
            session.close();
        }

        return true;
    } catch (err) {
        console.error("[PKCS#11] Init error:", err.message);
        CERTS = [];
        return false;
    }
}

// Helper to execute signing action with active logged-in RW session
async function withUserSession(action) {
    if (!mod) {
        await initPkcs11();
    }
    const slots = mod.getSlots(true);
    if (slots.length === 0) throw new Error("No token inserted or pcscd not running");
    const slot = slots.items(0);
    const session = slot.open(graphene.SessionFlag.SERIAL_SESSION | graphene.SessionFlag.RW_SESSION);

    try {
        if (config.pin) {
            try {
                session.login(config.pin);
            } catch (loginErr) {
                // If already logged in, continue
                if (!loginErr.message.includes("USER_ALREADY_LOGGED_IN")) {
                    throw loginErr;
                }
            }
        }
        return await action(session);
    } finally {
        try { session.logout(); } catch (e) {}
        try { session.close(); } catch (e) {}
    }
}

function findCert(key, val, nowMoment) {
    const now = nowMoment || moment();
    for (const c of CERTS) {
        if (key === "serial") {
            if (c.serial.toLowerCase() === (val || "").toLowerCase()) return c;
        } else if (key === "mst") {
            if (c.mst === val && now.isBetween(c.notBefore, c.notAfter)) return c;
        }
    }
    // Fallback: return first certificate if available
    return CERTS[0] || null;
}

// PDF Signing
async function signPdf(serial, nowMoment, pdfBuffer, sha256) {
    const cert = findCert("serial", serial, nowMoment);
    if (!cert) throw new Error(`Certificate with serial ${serial} not found or expired`);
    if (tokenNative.certs.length > 0 && tokenNative.privateKey) {
        return tokenNative.signPdf(cert, pdfBuffer, sha256);
    }


    return await withUserSession(async (session) => {
        const keys = session.find({ class: graphene.ObjectClass.PRIVATE_KEY });
        if (keys.length === 0) throw new Error("Private key not found on token");
        const privateKey = keys.items(0).toType();

        const algorithm = sha256 === 1 ? "SHA256_RSA_PKCS" : "SHA1_RSA_PKCS";
        const digestAlgorithm = sha256 === 1 ? forge.pki.oids.sha256 : forge.pki.oids.sha1;

        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(pdfBuffer.toString("binary"));
        p7.addCertificate(cert.certificate);

        const signer = {
            sign: (md, algo) => {
                const sign = session.createSign(algorithm, privateKey);
                return sign.once(pdfBuffer).toString("binary");
            }
        };

        p7.addSigner({
            key: signer,
            certificate: cert.certificate,
            digestAlgorithm: digestAlgorithm
        });

        p7.sign({ detached: true });
        const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
        return Buffer.from(raw, "binary").toString("base64");
    });
}

// XML Signing
function signdoc(session, privateKey, doc, id, keyInfo, ref, sha256) {
    const sig = new xmlcrypto.SignedXml();
    sig.id = id;
    let algorithm = "SHA1_RSA_PKCS";
    if (sha256 == 1) {
        algorithm = "SHA256_RSA_PKCS";
        sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        sig.addReference(ref, null, "http://www.w3.org/2001/04/xmlenc#sha256");
    } else {
        sig.addReference(ref);
    }
    sig.keyInfoProvider = keyInfo;
    const signedInfo = sig.createSignedInfo(doc);
    const signedInfoXml = signedInfo.replace("<SignedInfo>", "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">");
    const dummy = DOM.parseFromString(`<dummy>${signedInfoXml}</dummy>`);
    const canonXml = sig.getCanonXml(["http://www.w3.org/2001/10/xml-exc-c14n#"], dummy.documentElement.firstChild);
    const sign = session.createSign(algorithm, privateKey);
    sign.update(canonXml);
    const signedVal = sign.final().toString("base64");
    return { val: signedVal, info: signedInfo };
}

// Express App
const app = express();
app.use(cors());
app.use(express.json({ limit: "64mb" }));
app.use(express.urlencoded({ limit: "64mb", extended: true }));
app.use(requestIP.mw());

// Logging middleware
app.use((req, res, next) => {
    console.log(`[HTTP] ${req.method} ${req.url}`);
    next();
});

// Routes
app.get("/getVersion", (req, res) => {
    res.json("ok");
});

app.get("/reset", async (req, res) => {
    await initPkcs11();
    res.json("USBToken Signing has been reset");
});

app.get("/certs", async (req, res) => {
    if (CERTS.length === 0) await initPkcs11();
    const result = CERTS.map(c => ({
        cn: c.cn,
        serialNumber: c.serialNumber,
        fd: c.fd,
        td: c.td,
        cnInSubject: c.cnInSubject
    }));
    res.json(result);
});

app.get("/certs/:date", (req, res) => {
    const now = moment(Number(req.params.date));
    const arr = [];
    for (const c of CERTS) {
        if (now.isBetween(c.notBefore, c.notAfter)) {
            arr.push({ id: c.serial, value: c.info });
        }
    }
    res.json(arr);
});

app.get("/cert/:date", (req, res) => {
    const now = moment(Number(req.params.date));
    let json = null, ms1 = 1;
    for (const c of CERTS) {
        if (c.mst && now.isBetween(c.notBefore, c.notAfter)) {
            const ms2 = moment(c.notAfter).valueOf();
            if (ms2 > ms1) {
                ms1 = ms2;
                json = { mst: c.mst, subject: c.subject, issuer: c.issuer, serial: c.serial, fd: c.fd, td: c.td };
            }
        }
    }
    res.json(json);
});

app.get("/serial/:mst/:date", (req, res) => {
    const mst = req.params.mst;
    const now = moment(Number(req.params.date));
    const cert = findCert("mst", mst, now);
    if (!cert) return res.status(404).json({ error: `Not found certificate for MST ${mst}` });
    res.json({ serial: cert.serial, cn: cert.cnInSubject, _dataFindCert: {} });
});

app.post("/pdf", async (req, res) => {
    try {
        const body = req.body;
        const pdfBuf = Buffer.from(body.b64, "base64");
        const serial = body.serial;
        const now = moment(Number(body.time) || Date.now());

        console.log(`[SIGN-PDF] Received request to sign PDF (fn=${body.fn}, serial=${serial})`);
        let b64;
        try {
            b64 = await signPdf(serial, now, pdfBuf, 1);
        } catch (e1) {
            console.warn("[SIGN-PDF] SHA256 failed, falling back to SHA1:", e1.message);
            b64 = await signPdf(serial, now, pdfBuf, 0);
        }

        console.log(`[SIGN-PDF] Success! Signature length: ${b64.length}`);
        res.json({ fn: body.fn, offset: body.offset, b64: b64 });
    } catch (err) {
        console.error("[SIGN-PDF] Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

app.post(["/xml", "/xml/:decree"], async (req, res) => {
    try {
        const body = req.body;
        const mst = body.mst, arr = body.arr || [], signs = [], ids = [];
        console.log(`[SIGN-XML] Received request: decree=${req.params.decree || "standard"}, MST=${mst}, items=${arr.length}`);

        if (CERTS.length === 0) {
            await initPkcs11();
        }

        if (tokenNative.certs.length > 0 && tokenNative.privateKey) {
            for (const obj of arr) {
                const cert = findCert("mst", mst, moment(obj.idt));
                if (cert) {
                    const id = obj.inc;
                    const xml = Buffer.from(obj.xml, "base64").toString("utf-8");
                    const signFn = (canonSignedInfo, isSha256) => {
                        const signer = crypto.createSign(isSha256 ? "RSA-SHA256" : "RSA-SHA1");
                        signer.update(canonSignedInfo);
                        return signer.sign(tokenNative.privateKey).toString("base64");
                    };
                    const signedXml = signXmlDocument({
                        xml,
                        cert,
                        signFn,
                        id,
                        idt: obj.idt,
                        ref: obj.ref || body.ref,
                        signSample: obj.signSample,
                        sha256: 0
                    });
                    signs.push({ inc: id, xml: Buffer.from(signedXml).toString("base64") });
                    ids.push(id);
                }
            }
        } else {
            await withUserSession(async (session) => {
                const keys = session.find({ class: graphene.ObjectClass.PRIVATE_KEY });
                if (keys.length === 0) throw new Error("Private key not found");
                const privateKey = keys.items(0).toType();

                for (const obj of arr) {
                    const cert = findCert("mst", mst, moment(obj.idt));
                    if (cert) {
                        const id = obj.inc;
                        const xml = Buffer.from(obj.xml, "base64").toString("utf-8");
                        const signFn = (canonSignedInfo, isSha256) => {
                            const sign = session.createSign(isSha256 ? "SHA256_RSA_PKCS" : "SHA1_RSA_PKCS", privateKey);
                            sign.update(canonSignedInfo);
                            return sign.final().toString("base64");
                        };
                        const signedXml = signXmlDocument({
                            xml,
                            cert,
                            signFn,
                            id,
                            idt: obj.idt,
                            ref: obj.ref || body.ref,
                            signSample: obj.signSample,
                            sha256: 0
                        });
                        signs.push({ inc: id, xml: Buffer.from(signedXml).toString("base64") });
                        ids.push(id);
                    }
                }
            });
        }

        console.log(`[SIGN-XML] Completed signing: ${signs.length} document(s) signed successfully`);
        res.json({ incs: ids, signs: signs });
    } catch (err) {
        console.error("[SIGN-XML] Error:", err.message);
        res.status(500).json({ error: err.message });
    }
});

app.post("/upload", uploadXML, async (req, res) => {
    try {
        const body = req.body, buf = req.file.buffer;
        const date = Number(body.date), now = moment(date), ref = `//*[local-name(.)='${body.ref}']`, mst = body.mst;
        const cert = findCert(mst ? "mst" : "serial", mst || body.serial, now);
        if (!cert) throw new Error("Certificate not found");

        let signedXml;
        if (tokenNative.certs.length > 0 && tokenNative.privateKey) {
            const signFn = (canonSignedInfo, isSha256) => {
                const signer = crypto.createSign(isSha256 ? "RSA-SHA256" : "RSA-SHA1");
                signer.update(canonSignedInfo);
                return signer.sign(tokenNative.privateKey).toString("base64");
            };
            signedXml = signXmlDocument({
                xml: buf.toString("utf8"),
                cert,
                signFn,
                idt: now,
                ref,
                sha256: 0
            });
        } else {
            signedXml = await withUserSession(async (session) => {
                const keys = session.find({ class: graphene.ObjectClass.PRIVATE_KEY });
                if (keys.length === 0) throw new Error("Private key not found");
                const privateKey = keys.items(0).toType();
                const signFn = (canonSignedInfo, isSha256) => {
                    const sign = session.createSign(isSha256 ? "SHA256_RSA_PKCS" : "SHA1_RSA_PKCS", privateKey);
                    sign.update(canonSignedInfo);
                    return sign.final().toString("base64");
                };
                return signXmlDocument({
                    xml: buf.toString("utf8"),
                    cert,
                    signFn,
                    idt: now,
                    ref,
                    sha256: 0
                });
            });
        }

        res.json({ xml: signedXml });
    } catch (err) {
        console.error("[UPLOAD] Error:", err.message);
        res.json({ err: err.message });
    }
});

app.get("/status", (req, res) => {
    res.json({
        status: "running",
        port: config.port,
        pkcs11Driver: resolvePkcs11Module(),
        certsCount: CERTS.length,
        certs: CERTS.map(c => ({
            cn: c.cnInSubject,
            mst: c.mst,
            serial: c.serial,
            validTo: c.td
        }))
    });
});

app.get("/", (req, res) => {
    res.send(`
        <html>
            <head><title>FPT Signing Service (Linux)</title></head>
            <body style="font-family: sans-serif; padding: 30px;">
                <h2>🚀 FPT CA USB Signing Service (Linux / Headless)</h2>
                <p>Status: <strong>Running on port ${config.port}</strong></p>
                <p>PKCS#11 Library: <code>${resolvePkcs11Module()}</code></p>
                <p>Certificates Detected: <strong>${CERTS.length}</strong></p>
                <ul>
                    ${CERTS.map(c => `<li><strong>${c.cnInSubject}</strong> (MST: ${c.mst}, Serial: ${c.serial}, Valid until: ${c.td})</li>`).join("")}
                </ul>
                <hr/>
                <p><small>Endpoints: <code>/certs</code>, <code>/pdf</code>, <code>/xml</code>, <code>/upload</code>, <code>/reset</code>, <code>/status</code></small></p>
            </body>
        </html>
    `);
});

// Start Server
async function start() {
    await initPkcs11();
    app.listen(config.port, "127.0.0.1", () => {
        console.log(`\n======================================================`);
        console.log(`🚀 FPT USB Signing Service is listening on 127.0.0.1:${config.port}`);
        console.log(`📡 Ready to receive signing requests from web browser portals!`);
        console.log(`======================================================\n`);
    });
}

start();
