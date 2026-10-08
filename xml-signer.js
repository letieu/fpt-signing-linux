"use strict";

const crypto = require("crypto");
const xmlcrypto = require("xml-crypto");
const select = xmlcrypto.xpath;
const dom = require("xmldom").DOMParser;
const DOM = new dom();
const moment = require("moment");

const XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
const C14N_ALGO = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const ENVELOPED_SIG_ALGO = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

const escapeHtml = (text) => {
    if (!text) return "";
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;");
};

/**
 * Extracts or formats certificate subject string
 */
function getSubjectString(cert) {
    if (cert.subject) return cert.subject;
    if (cert.certificate && cert.certificate.subject) {
        try {
            return cert.certificate.subject.attributes
                .map(a => `${a.shortName || a.name}=${a.value}`)
                .join(", ");
        } catch (e) {}
    }
    return "";
}

/**
 * Signs an XML document conforming to Vietnam e-invoice (Nghị định 123 / Quyết định 1450/QĐ-TCT)
 * and W3C XMLDSig standard.
 *
 * @param {Object} params
 * @param {string|Buffer} params.xml - Input XML string or buffer
 * @param {Object} params.cert - Certificate object ({ c64, subject, certificate })
 * @param {Function} params.signFn - Function(canonSignedInfoBuffer, isSha256) => base64 signature
 * @param {string} [params.id] - Document incremental / transaction ID
 * @param {string|Date|moment.Moment} [params.idt] - Invoice creation date/time
 * @param {string} [params.ref] - Custom XPath reference selector
 * @param {Object} [params.signSample] - Optional signSample configuration from portal
 * @param {number|boolean} [params.sha256] - 1 for RSA-SHA256, 0 for RSA-SHA1 (default 0 as per TCT)
 * @returns {string} Signed XML string
 */
function signXmlDocument(params) {
    const { xml, cert, signFn, id, idt, ref, signSample, sha256 } = params;
    const isSha256 = sha256 === 1 || sha256 === true;
    const hashAlgo = isSha256 ? "sha256" : "sha1";
    const sigMethodUri = isSha256
        ? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        : "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    const digestMethodUri = isSha256
        ? "http://www.w3.org/2001/04/xmlenc#sha256"
        : "http://www.w3.org/2000/09/xmldsig#sha1";

    const xmlString = typeof xml === "string" ? xml : xml.toString("utf8");
    const doc = DOM.parseFromString(xmlString);

    // 1. Identify document structure & target element
    const dlhdonNodes = select(doc, "//*[local-name(.)='DLHDon']");
    const isHDon = dlhdonNodes.length > 0;
    let targetNode = null;
    let targetId = null;

    if (isHDon) {
        targetNode = dlhdonNodes[0];
        targetId = targetNode.getAttribute("Id");
        if (!targetId) {
            targetId = "DuLieuKy";
            targetNode.setAttribute("Id", targetId);
        }
    } else if (ref && ref !== "/*") {
        const customNodes = select(doc, ref);
        if (customNodes.length > 0) {
            targetNode = customNodes[0];
            targetId = targetNode.getAttribute("Id") || ("Ref-" + crypto.randomUUID().replace(/-/g, ""));
            if (!targetNode.getAttribute("Id")) targetNode.setAttribute("Id", targetId);
        }
    }

    if (!targetNode) {
        targetNode = doc.documentElement;
        targetId = targetNode.getAttribute("Id");
        if (!targetId) {
            targetId = "DuLieuKy";
            targetNode.setAttribute("Id", targetId);
        }
    }

    // 2. Determine Signature ID and Object ID
    let sigId = "Signature-" + (id ? `${id}-` : "") + crypto.randomUUID().replace(/-/g, "");
    if (signSample && signSample.tagBegin) {
        sigId = `${signSample.tagBegin}-${id || crypto.randomUUID().replace(/-/g, "")}`;
    }

    let objId = "SigningTime-" + crypto.randomUUID().replace(/-/g, "");
    let existingObjectInner = null;

    // Check if signSample.strReplaceTagSignEnd already defines an Object
    if (signSample && signSample.strReplaceTagSignEnd) {
        const objMatch = signSample.strReplaceTagSignEnd.match(/<Object[^>]*Id="([^"]+)"[^>]*>([\s\S]*?)<\/Object>/i);
        if (objMatch) {
            objId = objMatch[1];
            existingObjectInner = objMatch[2];
        }
    }

    // Determine SigningTime
    let signingTime = moment().format("YYYY-MM-DDTHH:mm:ss");
    if (idt) {
        const m = moment(idt);
        if (m.isValid()) signingTime = m.format("YYYY-MM-DDTHH:mm:ss");
    } else {
        const nlapNode = select(doc, "//*[local-name(.)='NLap']")[0];
        if (nlapNode && nlapNode.textContent) {
            const val = nlapNode.textContent.trim();
            if (val.length === 10) {
                signingTime = val + "T12:00:00";
            } else {
                const m = moment(val);
                if (m.isValid()) signingTime = m.format("YYYY-MM-DDTHH:mm:ss");
            }
        }
    }

    // 3. Build Object XML & Compute its digest
    // Note: Canonicalized Object must include XMLDSIG namespace declaration
    let objectXml;
    let objectXmlCanonWrapper;
    if (existingObjectInner) {
        objectXml = `<Object Id="${objId}">${existingObjectInner}</Object>`;
        objectXmlCanonWrapper = `<Object xmlns="${XMLDSIG_NS}" Id="${objId}">${existingObjectInner}</Object>`;
    } else {
        const innerProps = `<SignatureProperties xmlns=""><SignatureProperty Target="#${sigId}"><SigningTime>${signingTime}</SigningTime></SignatureProperty></SignatureProperties>`;
        objectXml = `<Object Id="${objId}">${innerProps}</Object>`;
        objectXmlCanonWrapper = `<Object xmlns="${XMLDSIG_NS}" Id="${objId}">${innerProps}</Object>`;
    }

    const s = new xmlcrypto.SignedXml();
    s.canonicalizationAlgorithm = C14N_ALGO;

    const objDoc = DOM.parseFromString(objectXmlCanonWrapper);
    const objCanon = s.getCanonXml([C14N_ALGO], objDoc.documentElement);
    const objDigest = crypto.createHash(hashAlgo).update(objCanon).digest("base64");

    // 4. Compute target element digest (DLHDon / data)
    const targetCanon = s.getCanonXml(
        [ENVELOPED_SIG_ALGO, C14N_ALGO],
        targetNode
    );
    const targetDigest = crypto.createHash(hashAlgo).update(targetCanon).digest("base64");

    // 5. Build SignedInfo XML
    const signedInfoXml = `<SignedInfo xmlns="${XMLDSIG_NS}"><CanonicalizationMethod Algorithm="${C14N_ALGO}"/><SignatureMethod Algorithm="${sigMethodUri}"/><Reference URI="#${targetId}"><Transforms><Transform Algorithm="${ENVELOPED_SIG_ALGO}"/></Transforms><DigestMethod Algorithm="${digestMethodUri}"/><DigestValue>${targetDigest}</DigestValue></Reference><Reference URI="#${objId}"><DigestMethod Algorithm="${digestMethodUri}"/><DigestValue>${objDigest}</DigestValue></Reference></SignedInfo>`;

    // 6. Canonicalize SignedInfo and compute digital signature
    const signedInfoDoc = DOM.parseFromString(signedInfoXml);
    const signedInfoCanon = s.getCanonXml([C14N_ALGO], signedInfoDoc.documentElement);
    const signatureValue = signFn(signedInfoCanon, isSha256);

    // 7. Build KeyInfo
    const certB64 = cert.c64 || (cert.value ? cert.value.toString("base64") : "");
    const subject = getSubjectString(cert);
    const subjectXml = subject ? `<X509SubjectName>${escapeHtml(subject)}</X509SubjectName>` : "";
    const keyInfoXml = `<KeyInfo><X509Data>${subjectXml}<X509Certificate>${certB64}</X509Certificate></X509Data></KeyInfo>`;

    // 8. Assemble complete Signature element
    const fullSignatureXml = `<Signature xmlns="${XMLDSIG_NS}" Id="${sigId}">${signedInfoXml}<SignatureValue>${signatureValue}</SignatureValue>${keyInfoXml}${objectXml}</Signature>`;
    const fullSigNode = DOM.parseFromString(fullSignatureXml).documentElement;

    // 9. Position Signature in XML Document
    if (isHDon) {
        let dscksNode = select(doc, "//*[local-name(.)='DSCKS']")[0];
        if (!dscksNode) {
            dscksNode = doc.createElement("DSCKS");
            doc.documentElement.appendChild(dscksNode);
        }

        let nbanNode = select(dscksNode, "./*[local-name(.)='NBan']")[0];
        if (!nbanNode) {
            nbanNode = doc.createElement("NBan");
            dscksNode.insertBefore(nbanNode, dscksNode.firstChild);
        }

        const existingSig = select(nbanNode, "./*[local-name(.)='Signature']")[0];
        if (existingSig) {
            nbanNode.removeChild(existingSig);
        }
        nbanNode.appendChild(fullSigNode);
        return doc.toString();
    } else {
        // Non-HDon XML
        if (signSample && signSample.xmlEndTagReplace && xmlString.includes(signSample.xmlEndTagReplace)) {
            return xmlString.replace(signSample.xmlEndTagReplace, fullSignatureXml + signSample.xmlEndTagReplace);
        }

        let dscksNode = select(doc, "//*[local-name(.)='DSCKS']/*[local-name(.)='NBan']")[0];
        if (dscksNode) {
            dscksNode.appendChild(fullSigNode);
        } else {
            doc.documentElement.appendChild(fullSigNode);
        }
        return doc.toString();
    }
}

module.exports = {
    signXmlDocument,
    XMLDSIG_NS,
    C14N_ALGO,
    ENVELOPED_SIG_ALGO,
};
