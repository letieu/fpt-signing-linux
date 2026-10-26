"use strict";

const fs = require("fs");
const forge = require("node-forge");
const { PDFDocument, rgb, StandardFonts } = require("pdf-lib");
const { pdflibAddPlaceholder } = require("@signpdf/placeholder-pdf-lib");
const { SignPdf } = require("@signpdf/signpdf");
const { Signer } = require("@signpdf/utils");
let fontkit = null;
try {
    fontkit = require("@pdf-lib/fontkit");
} catch (e) {
    console.warn("[PDF-Signer] fontkit optional module not loaded, using standard fonts.");
}

// Find system font for Vietnamese unicode text if available
function findSystemFont() {
    const candidates = [
        "/usr/share/fonts/TTF/Roboto-Regular.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/noto/NotoSans-Regular.ttf"
    ];
    for (const f of candidates) {
        if (fs.existsSync(f)) return f;
    }
    return null;
}

// Remove Vietnamese tones if falling back to standard Helvetica
function removeVietnameseTones(str) {
    if (!str) return "";
    return str
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/đ/g, "d")
        .replace(/Đ/g, "D");
}

class TokenSigner extends Signer {
    constructor(certEntry, signFn) {
        super();
        this.certEntry = certEntry;
        this.signFn = signFn;
    }

    async sign(pdfBuffer) {
        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(pdfBuffer.toString("binary"));
        p7.addCertificate(this.certEntry.certificate);

        const signer = {
            sign: () => {
                return this.signFn(pdfBuffer);
            }
        };

        p7.addSigner({
            key: signer,
            certificate: this.certEntry.certificate,
            digestAlgorithm: forge.pki.oids.sha256
        });

        p7.sign({ detached: true });
        const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
        return Buffer.from(raw, "binary");
    }
}

/**
 * Sign a PDF document
 * @param {Object} options
 * @param {Buffer} options.pdfBuffer - Raw input PDF buffer
 * @param {Object} options.certEntry - Certificate entry from tokenNative or PKCS#11
 * @param {Function} options.signFn - Function (dataBuffer) => binaryString (RSA signature)
 * @param {string} [options.signatureType='embedded'] - 'embedded' | 'detached' | 'both'
 * @param {boolean} [options.visible=true] - Draw visible signature stamp
 * @param {string} [options.position='bottom-right'] - 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left'
 * @param {string|number} [options.page='last'] - 'last' | 'first' | 1-based page number
 * @param {string} [options.reason='Xác nhận văn bản điện tử']
 * @param {string} [options.location='Việt Nam']
 */
async function signPdfDocument(options) {
    const {
        pdfBuffer,
        certEntry,
        signFn,
        signatureType = "embedded",
        visible = true,
        position = "bottom-right",
        page = "last",
        reason = "Xác nhận văn bản điện tử",
        location = "Việt Nam"
    } = options;

    if (!pdfBuffer || !Buffer.isBuffer(pdfBuffer)) {
        throw new Error("Invalid or empty PDF buffer");
    }
    if (!certEntry || !certEntry.certificate) {
        throw new Error("Invalid certificate entry");
    }
    if (typeof signFn !== "function") {
        throw new Error("signFn must be a function");
    }

    // 1. Generate detached PKCS#7 signature if requested
    let detachedP7sBuffer = null;
    if (signatureType === "detached" || signatureType === "both") {
        const p7 = forge.pkcs7.createSignedData();
        p7.content = forge.util.createBuffer(pdfBuffer.toString("binary"));
        p7.addCertificate(certEntry.certificate);

        const signer = {
            sign: () => signFn(pdfBuffer)
        };

        p7.addSigner({
            key: signer,
            certificate: certEntry.certificate,
            digestAlgorithm: forge.pki.oids.sha256
        });

        p7.sign({ detached: true });
        const raw = forge.asn1.toDer(p7.toAsn1()).getBytes();
        detachedP7sBuffer = Buffer.from(raw, "binary");

        if (signatureType === "detached") {
            return {
                signedPdfBuffer: null,
                detachedP7sBuffer,
                certInfo: {
                    cn: certEntry.cnInSubject,
                    serial: certEntry.serial,
                    mst: certEntry.mst
                }
            };
        }
    }

    // 2. Load PDF with pdf-lib for embedded signing
    const doc = await PDFDocument.load(pdfBuffer);
    const pages = doc.getPages();
    if (pages.length === 0) {
        throw new Error("PDF has no pages");
    }

    let targetPageIdx = pages.length - 1;
    if (page === "first" || page === 1 || page === "1") {
        targetPageIdx = 0;
    } else if (typeof page === "number" && page > 0 && page <= pages.length) {
        targetPageIdx = page - 1;
    } else if (!isNaN(parseInt(page, 10))) {
        const pNum = parseInt(page, 10);
        if (pNum >= 1 && pNum <= pages.length) targetPageIdx = pNum - 1;
    }
    const targetPage = pages[targetPageIdx];
    const { width: pageWidth, height: pageHeight } = targetPage.getSize();

    // Prepare fonts
    let regularFont, boldFont;
    let supportsUnicode = false;
    const systemFontPath = findSystemFont();

    if (fontkit && systemFontPath) {
        try {
            doc.registerFontkit(fontkit);
            const fontBytes = fs.readFileSync(systemFontPath);
            regularFont = await doc.embedFont(fontBytes);
            boldFont = regularFont; // subset font
            supportsUnicode = true;
        } catch (e) {
            console.warn("[PDF-Signer] System font loading failed, fallback to Helvetica:", e.message);
        }
    }

    if (!supportsUnicode) {
        regularFont = await doc.embedFont(StandardFonts.Helvetica);
        boldFont = await doc.embedFont(StandardFonts.HelveticaBold);
    }

    const stampWidth = (options.coords && options.coords.width) ? options.coords.width : 250;
    const stampHeight = (options.coords && options.coords.height) ? options.coords.height : 62;
    const margin = 35;

    let stampX, stampY;
    if (options.coords && typeof options.coords.x === "number" && typeof options.coords.y === "number") {
        stampX = Math.max(0, Math.min(pageWidth - stampWidth, options.coords.x));
        stampY = Math.max(0, Math.min(pageHeight - stampHeight, options.coords.y));
    } else {
        switch (position) {
            case "top-left":
                stampX = margin;
                stampY = pageHeight - stampHeight - margin;
                break;
            case "top-right":
                stampX = pageWidth - stampWidth - margin;
                stampY = pageHeight - stampHeight - margin;
                break;
            case "bottom-left":
                stampX = margin;
                stampY = margin;
                break;
            case "bottom-right":
            default:
                stampX = pageWidth - stampWidth - margin;
                stampY = margin;
                break;
        }
    }

    const formatText = (text) => supportsUnicode ? text : removeVietnameseTones(text);

    let widgetRect = [0, 0, 0, 0];
    if (visible) {
        widgetRect = [stampX, stampY, stampX + stampWidth, stampY + stampHeight];

        // Draw Stamp Box: Clean e-Signature Stamp with Green accent border
        targetPage.drawRectangle({
            x: stampX,
            y: stampY,
            width: stampWidth,
            height: stampHeight,
            borderColor: rgb(0.12, 0.58, 0.26), // Green #1e8e3e
            borderWidth: 1.2,
            color: rgb(0.98, 1, 0.98),
            opacity: 0.96
        });

        // Decorative left green bar
        targetPage.drawRectangle({
            x: stampX,
            y: stampY,
            width: 4,
            height: stampHeight,
            color: rgb(0.12, 0.58, 0.26)
        });

        const signTitle = formatText("✔ Signature valid");
        const companyName = formatText(certEntry.cnInSubject || "CÔNG TY KÝ SỐ");
        const signDate = new Date().toISOString().replace("T", " ").substring(0, 19);
        const signDateText = formatText(`Ngày ký: ${signDate}`);

        // Line 1: Signature valid
        targetPage.drawText(signTitle, {
            x: stampX + 12,
            y: stampY + stampHeight - 17,
            size: 9.5,
            font: boldFont,
            color: rgb(0.12, 0.58, 0.26)
        });

        // Line 2: Được ký bởi: [COMPANY NAME]
        const maxLen = 36;
        const dispName = companyName.length > maxLen ? companyName.substring(0, maxLen - 3) + "..." : companyName;
        const line2Text = formatText(`Được ký bởi: ${dispName}`);

        targetPage.drawText(line2Text, {
            x: stampX + 12,
            y: stampY + stampHeight - 33,
            size: 8,
            font: boldFont,
            color: rgb(0.12, 0.12, 0.12)
        });

        // Line 3: Ngày ký: YYYY-MM-DD HH:mm:ss
        targetPage.drawText(signDateText, {
            x: stampX + 12,
            y: stampY + stampHeight - 48,
            size: 8,
            font: regularFont,
            color: rgb(0.3, 0.3, 0.3)
        });
    }

    // Add Signature Placeholder
    pdflibAddPlaceholder({
        pdfDoc: doc,
        reason: removeVietnameseTones(reason),
        contactInfo: "",
        name: removeVietnameseTones(certEntry.cnInSubject || "Signer"),
        location: removeVietnameseTones(location),
        signatureLength: 8192,
        widgetRect: widgetRect
    });

    const pdfWithPlaceholder = await doc.save({ useObjectStreams: false });
    const signPdf = new SignPdf();
    const tokenSigner = new TokenSigner(certEntry, signFn);
    const signedPdfBuffer = await signPdf.sign(Buffer.from(pdfWithPlaceholder), tokenSigner);

    return {
        signedPdfBuffer,
        detachedP7sBuffer,
        certInfo: {
            cn: certEntry.cnInSubject,
            serial: certEntry.serial,
            mst: certEntry.mst,
            validTo: certEntry.td
        }
    };
}

module.exports = {
    signPdfDocument,
    removeVietnameseTones
};
