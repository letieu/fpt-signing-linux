"use strict";

const cp = require("child_process");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const forge = require("node-forge");
const moment = require("moment");
const xmlcrypto = require("xml-crypto");
const dom = require("xmldom").DOMParser;
const DOM = new dom();
const { signXmlDocument } = require("./xml-signer");
const DTF = "YYYY-MM-DD HH:mm:ss";
const TOOL_PATH = path.join(__dirname, "bin", "epass2003-tool");

function encodeDerInteger(b) {
    let start = 0;
    while (start < b.length && b[start] === 0) start++;
    const trimmed = b.slice(start);
    if (trimmed.length === 0) return Buffer.from([0x02, 0x01, 0x00]);
    const needZero = (trimmed[0] & 0x80) !== 0;
    const len = trimmed.length + (needZero ? 1 : 0);
    const header = [0x02];
    if (len < 128) {
        header.push(len);
    } else if (len < 256) {
        header.push(0x81, len);
    } else {
        header.push(0x82, (len >> 8) & 0xff, len & 0xff);
    }
    const chunks = [Buffer.from(header)];
    if (needZero) chunks.push(Buffer.from([0x00]));
    chunks.push(trimmed);
    return Buffer.concat(chunks);
}

function encodeDerSequence(chunks) {
    const body = Buffer.concat(chunks);
    const len = body.length;
    const header = [0x30];
    if (len < 128) {
        header.push(len);
    } else if (len < 256) {
        header.push(0x81, len);
    } else {
        header.push(0x82, (len >> 8) & 0xff, len & 0xff);
    }
    return Buffer.concat([Buffer.from(header), body]);
}

function parsePrivateKey24A0(buf) {
    let offset = 0;
    const tags = {};
    while (offset < buf.length - 8) {
        const tagId = buf.readUInt32LE(offset);
        const tagLen = buf.readUInt32LE(offset + 4);
        if (tagLen > 0 && tagLen <= 512 && offset + 8 + tagLen <= buf.length) {
            tags[tagId.toString(16)] = buf.slice(offset + 8, offset + 8 + tagLen);
            offset += 8 + tagLen;
        } else {
            offset++;
        }
    }

    const n = tags["120"];
    const e = tags["122"];
    const d = tags["123"];
    const p = tags["124"];
    const q = tags["125"];
    const dmp1 = tags["126"];
    const dmq1 = tags["127"];
    const iqmp = tags["128"];

    if (!n || !e || !d || !p || !q) {
        throw new Error("Missing RSA key components in 24A0");
    }

    const rsaPrivateKeyDer = encodeDerSequence([
        Buffer.from([0x02, 0x01, 0x00]), // version 0
        encodeDerInteger(n),
        encodeDerInteger(e),
        encodeDerInteger(d),
        encodeDerInteger(p),
        encodeDerInteger(q),
        encodeDerInteger(dmp1),
        encodeDerInteger(dmq1),
        encodeDerInteger(iqmp)
    ]);

    const cryptoKey = crypto.createPrivateKey({
        key: rsaPrivateKeyDer,
        format: "der",
        type: "pkcs1"
    });

    const asn1 = forge.asn1.fromDer(rsaPrivateKeyDer.toString("binary"));
    const forgeKey = forge.pki.privateKeyFromAsn1(asn1);

    return { cryptoKey, forgeKey, rsaPrivateKeyDer };
}

function checkmst(mst) {
    if (!(/^[0-9]{10}$|^[0-9]{10}\-[0-9]{3}$/.test(mst))) return false;
    const ms = [];
    for (let i = 0; i < 10; i++) ms.push(parseInt(mst.charAt(i), 10));
    const a = 31 * ms[0] + 29 * ms[1] + 23 * ms[2] + 19 * ms[3] + 17 * ms[4] + 13 * ms[5] + 7 * ms[6] + 5 * ms[7] + 3 * ms[8];
    return ms[9] === 10 - (a % 11);
}

function getmst(sub) {
    for (const obj of sub.attributes) {
        const type = obj.type;
        if (type == "0.9.2342.19200300.100.1.1" || type == "2.5.4.10" || type == "2.5.4.3" || type == "2.5.4.8") {
            const arr = obj.value.split(":");
            let mst = arr[arr.length - 1].trim();
            if (/^[0-9]{10}[0-9]{3}$/.test(mst)) mst = `${mst.substr(0, 10)}-${mst.substr(10)}`;
            if (checkmst(mst)) return mst;
        }
    }
    return null;
}

function getSubjectCirculars78(obj) {
    return obj.attributes.map(attr => {
        const sn = attr.shortName, regex = /^MST\:\d{10}(\-\d{3})*$/;
        let val = attr.value;
        try { val = forge.util.decodeUtf8(val); } catch (e) {}
        let bonusVal = val;
        if (regex.test(attr.value)) bonusVal = `${attr.type}${attr.value}`;
        return sn ? [sn, bonusVal].join("=") : [attr.type, val].join("=");
    }).join(", ");
}

function getdtl(obj) {
    return obj.attributes.map(attr => {
        const sn = attr.shortName, regex = /^MST\:\d{10}(\-\d{3})*$/;
        let val = attr.value;
        try { val = forge.util.decodeUtf8(val); } catch (e) {}
        let bonusVal = val;
        if (regex.test(attr.value)) bonusVal = `${attr.type}${attr.value}`;
        return sn ? [sn, bonusVal].join("=") : val;
    }).join(", ");
}

function getCnInSubject(obj) {
    for (const attr of obj.attributes) {
        if (attr.shortName === "CN") {
            try { return forge.util.decodeUtf8(attr.value); } catch (e) { return attr.value; }
        }
    }
    return "";
}

class TokenNative {
    constructor() {
        this.certs = [];
        this.privateKey = null;
        this.forgePrivateKey = null;
    }

    isAvailable() {
        return fs.existsSync(TOOL_PATH);
    }

    init(pin) {
        if (!fs.existsSync(TOOL_PATH)) {
            throw new Error(`Tool not found at ${TOOL_PATH}`);
        }

        console.log(`[TokenNative] Accessing Feitian ePass2003 via native driver...`);

        // 1. Read DER Certificate
        let certDer;
        try {
            certDer = cp.execFileSync(TOOL_PATH, ["read-cert"]);
        } catch (e) {
            throw new Error("Failed to read certificate from token: " + (e.stderr ? e.stderr.toString() : e.message));
        }

        if (!certDer || certDer.length === 0) {
            throw new Error("Empty certificate read from token");
        }

        // 2. Read Key with PIN verification
        let keyRaw;
        try {
            keyRaw = cp.execFileSync(TOOL_PATH, ["read-key", pin || ""]);
        } catch (e) {
            const errMsg = e.stderr ? e.stderr.toString() : e.message;
            throw new Error("Failed to authenticate/read private key: " + errMsg);
        }

        const { cryptoKey, forgeKey } = parsePrivateKey24A0(keyRaw);
        this.privateKey = cryptoKey;
        this.forgePrivateKey = forgeKey;

        // Parse certificate
        const forgeCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(certDer.toString("binary")));
        const validity = forgeCert.validity;
        const notBefore = validity.notBefore;
        const notAfter = validity.notAfter;
        const serial = forgeCert.serialNumber;
        const subject = forgeCert.subject;
        const issuer = forgeCert.issuer;
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
            c64: certDer.toString("base64"),
            info: `#${mst || ""}#${scn}#${fd.format("YYYY-MM-DD")}..${td.format("YYYY-MM-DD")}`,
            certificate: forgeCert,
            privateKey: cryptoKey,
            forgePrivateKey: forgeKey
        };

        this.certs = [entry];
        console.log(`[TokenNative] Loaded Cert: ${scn} (Serial: ${serial}, MST: ${mst})`);
        console.log(`[TokenNative] Valid: ${entry.fd} -> ${entry.td}`);
        return this.certs;
    }

    signXml(doc, id, keyInfo, ref, sha256) {
        if (!this.privateKey) throw new Error("Private key not initialized");

        const sig = new xmlcrypto.SignedXml();
        sig.id = id;
        let algorithm = "RSA-SHA1";
        if (sha256 == 1) {
            algorithm = "RSA-SHA256";
            sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
            sig.addReference(ref, null, "http://www.w3.org/2001/04/xmlenc#sha256");
        } else {
            sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            sig.addReference(ref);
        }
        sig.keyInfoProvider = keyInfo;

        const signedInfo = sig.createSignedInfo(doc);
        const signedInfoXml = signedInfo.replace("<SignedInfo>", '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">');
        const dummy = DOM.parseFromString(`<dummy>${signedInfoXml}</dummy>`);
        const canonXml = sig.getCanonXml([sig.canonicalizationAlgorithm], dummy.documentElement.firstChild);

        const signer = crypto.createSign(algorithm);
        signer.update(canonXml);
        const signedVal = signer.sign(this.privateKey).toString("base64");

        return { val: signedVal, info: signedInfo };
    }

    signXmlDocument(params) {
        if (!this.privateKey) throw new Error("Private key not initialized");
        const cert = params.cert || this.certs[0];
        const signFn = (canonSignedInfo, isSha256) => {
            const signer = crypto.createSign(isSha256 ? "RSA-SHA256" : "RSA-SHA1");
            signer.update(canonSignedInfo);
            return signer.sign(this.privateKey).toString("base64");
        };
        return signXmlDocument({
            ...params,
            cert,
            signFn
        });
    }

    signPdf(cert, pdfBuf, sha256) {
        if (!this.privateKey) throw new Error("Private key not initialized");

        const algorithm = sha256 === 1 ? "RSA-SHA256" : "RSA-SHA1";
        const digestAlgorithm = sha256 === 1 ? forge.pki.oids.sha256 : forge.pki.oids.sha1;

        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(pdfBuf.toString("binary"));
        p7.addCertificate(cert.certificate);

        const signer = {
            sign: () => {
                const s = crypto.createSign(algorithm);
                s.update(pdfBuf);
                return s.sign(this.privateKey).toString("binary");
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
    }
}

module.exports = new TokenNative();
