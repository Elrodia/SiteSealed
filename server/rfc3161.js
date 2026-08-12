import {
  X509Certificate,
  constants,
  createHash,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { OctetString, Sequence, fromBER } from "asn1js";
import {
  AlgorithmIdentifier,
  Certificate,
  CertificateChainValidationEngine,
  ContentInfo,
  IssuerAndSerialNumber,
  RSASSAPSSParams,
  SignedData,
  TSTInfo,
} from "pkijs";

export const RFC3161_VALIDATOR_VERSION =
  "SITESEALED_RFC3161_VALIDATOR_V1";

export const EVIDENCY_SANDBOX_ROOT_SHA256 =
  "6871a6ed629cbefd77caee74a6bf6a9c22d96a8c26065dac75651e2e36a8b62d";
export const EVIDENCY_SANDBOX_TIMESTAMP_CA_SHA256 =
  "05d89655a8bd51ec3100a9d062432b19ce018f861c9e209d50026c7e6322597b";

const CMS_SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
const TST_INFO_OID = "1.2.840.113549.1.9.16.1.4";
const CONTENT_TYPE_ATTRIBUTE_OID = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST_ATTRIBUTE_OID = "1.2.840.113549.1.9.4";
const CMS_ALGORITHM_PROTECTION_ATTRIBUTE_OID = "1.2.840.113549.1.9.52";
const SIGNING_CERTIFICATE_V2_ATTRIBUTE_OID =
  "1.2.840.113549.1.9.16.2.47";
const TIMESTAMPING_EKU_OID = "1.3.6.1.5.5.7.3.8";
const EXTENDED_KEY_USAGE_OID = "2.5.29.37";
const KEY_USAGE_OID = "2.5.29.15";
const BASIC_CONSTRAINTS_OID = "2.5.29.19";
const MGF1_OID = "1.2.840.113549.1.1.8";
const RSA_ENCRYPTION_OID = "1.2.840.113549.1.1.1";
const RSA_PSS_OID = "1.2.840.113549.1.1.10";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const SERIAL_PATTERN = /^(?:0x)?[a-f0-9:]+$/i;
const OID_PATTERN = /^(?:0|1|2)(?:\.(?:0|[1-9]\d*))+$/;
const MAX_TOKEN_BYTES = 2 * 1024 * 1024;

const HASH_ALGORITHMS = new Map([
  [
    "2.16.840.1.101.3.4.2.1",
    { nodeName: "sha256", displayName: "SHA256", digestBytes: 32 },
  ],
  [
    "2.16.840.1.101.3.4.2.2",
    { nodeName: "sha384", displayName: "SHA384", digestBytes: 48 },
  ],
  [
    "2.16.840.1.101.3.4.2.3",
    { nodeName: "sha512", displayName: "SHA512", digestBytes: 64 },
  ],
]);

const SIGNATURE_ALGORITHMS = new Map([
  [
    "1.2.840.113549.1.1.11",
    { kind: "rsa-pkcs1", hashOid: "2.16.840.1.101.3.4.2.1", displayName: "RSA_PKCS1_SHA256" },
  ],
  [
    "1.2.840.113549.1.1.12",
    { kind: "rsa-pkcs1", hashOid: "2.16.840.1.101.3.4.2.2", displayName: "RSA_PKCS1_SHA384" },
  ],
  [
    "1.2.840.113549.1.1.13",
    { kind: "rsa-pkcs1", hashOid: "2.16.840.1.101.3.4.2.3", displayName: "RSA_PKCS1_SHA512" },
  ],
  [
    "1.2.840.10045.4.3.2",
    { kind: "ecdsa", hashOid: "2.16.840.1.101.3.4.2.1", displayName: "ECDSA_SHA256" },
  ],
  [
    "1.2.840.10045.4.3.3",
    { kind: "ecdsa", hashOid: "2.16.840.1.101.3.4.2.2", displayName: "ECDSA_SHA384" },
  ],
  [
    "1.2.840.10045.4.3.4",
    { kind: "ecdsa", hashOid: "2.16.840.1.101.3.4.2.3", displayName: "ECDSA_SHA512" },
  ],
]);

const defaultRootPem = readFileSync(
  new URL("./trust/evidency-sandbox-root-ca.pem", import.meta.url),
  "utf8",
);
const defaultTimestampCaPem = readFileSync(
  new URL("./trust/evidency-sandbox-timestamp-ca.pem", import.meta.url),
  "utf8",
);

export class Rfc3161VerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "Rfc3161VerificationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new Rfc3161VerificationError(code, message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function equalBytes(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function canonicalSerial(value, label = "serial number") {
  const text = String(value ?? "").trim();
  if (!text || !SERIAL_PATTERN.test(text)) {
    fail("INVALID_EXPECTED_VALUE", `The ${label} is not valid hexadecimal.`);
  }
  const normalized = text.toLowerCase().replace(/^0x/, "").replaceAll(":", "");
  if (!normalized) {
    fail("INVALID_EXPECTED_VALUE", `The ${label} is not valid hexadecimal.`);
  }
  return normalized.replace(/^0+/, "") || "0";
}

function integerHex(integer) {
  const bytes = Buffer.from(integer.valueBlock.valueHexView);
  if (bytes.length === 0 || (bytes[0] & 0x80) !== 0) {
    fail("TSTINFO_SERIAL_INVALID", "The RFC 3161 serial number must be a positive integer.");
  }
  return canonicalSerial(
    bytes.toString("hex"),
    "token serial number",
  );
}

function parseCertificate(pem, expectedSha256, role) {
  let x509;
  try {
    x509 = new X509Certificate(pem);
  } catch {
    fail("TRUST_BUNDLE_INVALID", `The pinned ${role} certificate is unreadable.`);
  }
  const raw = Buffer.from(x509.raw);
  const fingerprint = sha256(raw);
  if (fingerprint !== expectedSha256) {
    fail(
      "TRUST_BUNDLE_INTEGRITY_FAILED",
      `The pinned ${role} certificate fingerprint does not match the release manifest.`,
    );
  }
  let pkijs;
  try {
    pkijs = Certificate.fromBER(raw);
  } catch {
    fail("TRUST_BUNDLE_INVALID", `The pinned ${role} certificate is malformed.`);
  }
  return { x509, pkijs, raw, fingerprint };
}

export function createEvidencySandboxTrustStore({
  rootPem = defaultRootPem,
  timestampCaPem = defaultTimestampCaPem,
  rootSha256 = EVIDENCY_SANDBOX_ROOT_SHA256,
  timestampCaSha256 = EVIDENCY_SANDBOX_TIMESTAMP_CA_SHA256,
} = {}) {
  const root = parseCertificate(rootPem, rootSha256, "sandbox root CA");
  const timestampCa = parseCertificate(
    timestampCaPem,
    timestampCaSha256,
    "sandbox timestamp CA",
  );

  if (!root.x509.ca || !root.x509.checkIssued(root.x509) || !root.x509.verify(root.x509.publicKey)) {
    fail("TRUST_BUNDLE_INVALID", "The pinned sandbox root CA is not a valid self-signed CA.");
  }
  if (
    !timestampCa.x509.ca ||
    !timestampCa.x509.checkIssued(root.x509) ||
    !timestampCa.x509.verify(root.x509.publicKey)
  ) {
    fail(
      "TRUST_BUNDLE_INVALID",
      "The pinned sandbox timestamp CA does not validate to the pinned root CA.",
    );
  }

  return { root, timestampCa };
}

let defaultTrustStore;

function getDefaultTrustStore() {
  defaultTrustStore ??= createEvidencySandboxTrustStore();
  return defaultTrustStore;
}

function requireSingleAttribute(attributes, oid, label) {
  const matches = attributes.filter((attribute) => attribute.type === oid);
  if (matches.length !== 1 || matches[0].values.length !== 1) {
    fail(
      "SIGNED_ATTRIBUTE_INVALID",
      `The CMS signer must contain exactly one ${label} signed attribute.`,
    );
  }
  return matches[0].values[0];
}

function optionalSingleAttribute(attributes, oid, label) {
  const matches = attributes.filter((attribute) => attribute.type === oid);
  if (matches.length > 1 || (matches[0] && matches[0].values.length !== 1)) {
    fail(
      "SIGNED_ATTRIBUTE_INVALID",
      `The CMS signer contains an invalid ${label} signed attribute.`,
    );
  }
  return matches[0]?.values[0] ?? null;
}

function algorithmIdentifierFromImplicit(value) {
  if (
    value?.idBlock?.tagClass !== 3 ||
    value?.idBlock?.tagNumber !== 1 ||
    !value?.idBlock?.isConstructed
  ) {
    fail(
      "ALGORITHM_PROTECTION_INVALID",
      "The CMS algorithm-protection signature algorithm is malformed.",
    );
  }
  return new AlgorithmIdentifier({
    schema: new Sequence({ value: value.valueBlock.value }),
  });
}

function algorithmIdentifierDer(value) {
  return Buffer.from(value.toSchema().toBER(false));
}

function verifyCmsAlgorithmProtection(value, signerInfo) {
  if (!value) return "NOT_PRESENT";
  const children = value?.valueBlock?.value;
  if (!Array.isArray(children) || children.length !== 2) {
    fail(
      "ALGORITHM_PROTECTION_INVALID",
      "The CMS algorithm-protection attribute is malformed.",
    );
  }
  let digestAlgorithm;
  try {
    digestAlgorithm = new AlgorithmIdentifier({ schema: children[0] });
  } catch {
    fail(
      "ALGORITHM_PROTECTION_INVALID",
      "The CMS algorithm-protection digest algorithm is malformed.",
    );
  }
  const signatureAlgorithm = algorithmIdentifierFromImplicit(children[1]);
  if (
    !equalBytes(
      algorithmIdentifierDer(digestAlgorithm),
      algorithmIdentifierDer(signerInfo.digestAlgorithm),
    ) ||
    !equalBytes(
      algorithmIdentifierDer(signatureAlgorithm),
      algorithmIdentifierDer(signerInfo.signatureAlgorithm),
    )
  ) {
    fail(
      "ALGORITHM_PROTECTION_MISMATCH",
      "The signed CMS algorithm-protection attribute does not match SignerInfo.",
    );
  }
  return "VALID";
}

function hashAlgorithmForOid(oid, context) {
  const algorithm = HASH_ALGORITHMS.get(oid);
  if (!algorithm) {
    fail(
      "UNSUPPORTED_HASH_ALGORITHM",
      `${context} uses an unsupported or deprecated hash algorithm.`,
    );
  }
  return algorithm;
}

function verifySigningCertificateV2(value, signerCertificateRaw) {
  const outer = value?.valueBlock?.value;
  const certSequence = outer?.[0]?.valueBlock?.value;
  if (!Array.isArray(certSequence) || certSequence.length !== 1) {
    fail(
      "SIGNING_CERTIFICATE_V2_INVALID",
      "The signingCertificateV2 attribute must bind exactly one signer certificate.",
    );
  }
  const essCertId = certSequence[0]?.valueBlock?.value;
  if (!Array.isArray(essCertId) || essCertId.length < 1 || essCertId.length > 3) {
    fail(
      "SIGNING_CERTIFICATE_V2_INVALID",
      "The signingCertificateV2 ESSCertIDv2 value is malformed.",
    );
  }

  let index = 0;
  let hashAlgorithm = HASH_ALGORITHMS.get("2.16.840.1.101.3.4.2.1");
  if (essCertId[index] instanceof Sequence) {
    let identifier;
    try {
      identifier = new AlgorithmIdentifier({ schema: essCertId[index] });
    } catch {
      fail(
        "SIGNING_CERTIFICATE_V2_INVALID",
        "The signingCertificateV2 hash algorithm is malformed.",
      );
    }
    hashAlgorithm = hashAlgorithmForOid(
      identifier.algorithmId,
      "The signingCertificateV2 attribute",
    );
    index += 1;
  }
  const certHash = essCertId[index];
  if (!(certHash instanceof OctetString)) {
    fail(
      "SIGNING_CERTIFICATE_V2_INVALID",
      "The signingCertificateV2 certificate hash is missing.",
    );
  }
  const expected = createHash(hashAlgorithm.nodeName)
    .update(signerCertificateRaw)
    .digest();
  if (!equalBytes(expected, certHash.valueBlock.valueHexView)) {
    fail(
      "SIGNING_CERTIFICATE_V2_MISMATCH",
      "The signed ESSCertIDv2 does not identify the CMS signer certificate.",
    );
  }
  return {
    status: "ESSCERTIDV2_MATCH",
    hashAlgorithm: hashAlgorithm.displayName,
  };
}

async function findSignerCertificate(signedData, signerInfo) {
  const certificates = (signedData.certificates ?? []).filter(
    (certificate) => certificate instanceof Certificate,
  );
  const matches = [];
  if (signerInfo.sid instanceof IssuerAndSerialNumber) {
    for (const certificate of certificates) {
      if (
        certificate.issuer.isEqual(signerInfo.sid.issuer) &&
        certificate.serialNumber.isEqual(signerInfo.sid.serialNumber)
      ) {
        matches.push(certificate);
      }
    }
  } else {
    const keyId = Buffer.from(
      signerInfo.sid.idBlock.isConstructed
        ? signerInfo.sid.valueBlock.value[0].valueBlock.valueHexView
        : signerInfo.sid.valueBlock.valueHexView,
    );
    for (const certificate of certificates) {
      const subjectPublicKey = Buffer.from(
        certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView,
      );
      if (equalBytes(createHash("sha1").update(subjectPublicKey).digest(), keyId)) {
        matches.push(certificate);
      }
    }
  }
  if (matches.length !== 1) {
    fail(
      "SIGNER_CERTIFICATE_NOT_UNIQUE",
      "The CMS signer certificate could not be identified uniquely.",
    );
  }
  return matches[0];
}

function extension(certificate, oid, label) {
  const matches = (certificate.extensions ?? []).filter(
    (item) => item.extnID === oid,
  );
  if (matches.length !== 1) {
    fail(
      "SIGNER_CERTIFICATE_PROFILE_INVALID",
      `The timestamp signer certificate must contain exactly one ${label} extension.`,
    );
  }
  return matches[0];
}

export function assertTimestampSignerProfile(certificate, x509) {
  const basicConstraints = extension(
    certificate,
    BASIC_CONSTRAINTS_OID,
    "basicConstraints",
  );
  if (!basicConstraints.critical || basicConstraints.parsedValue?.cA === true || x509.ca) {
    fail(
      "SIGNER_CERTIFICATE_PROFILE_INVALID",
      "The timestamp signer certificate must be a critical non-CA end-entity certificate.",
    );
  }

  const extendedKeyUsage = extension(
    certificate,
    EXTENDED_KEY_USAGE_OID,
    "extendedKeyUsage",
  );
  const purposes = extendedKeyUsage.parsedValue?.keyPurposes;
  if (
    !extendedKeyUsage.critical ||
    !Array.isArray(purposes) ||
    purposes.length !== 1 ||
    purposes[0] !== TIMESTAMPING_EKU_OID
  ) {
    fail(
      "SIGNER_CERTIFICATE_PROFILE_INVALID",
      "The signer certificate EKU must be critical and contain only id-kp-timeStamping.",
    );
  }

  const keyUsage = extension(certificate, KEY_USAGE_OID, "keyUsage");
  const keyUsageBytes = Buffer.from(
    keyUsage.parsedValue?.valueBlock?.valueHexView ?? [],
  );
  if (
    !keyUsage.critical ||
    keyUsageBytes.length !== 1 ||
    (keyUsageBytes[0] & 0xc0) === 0 ||
    (keyUsageBytes[0] & 0x3f) !== 0
  ) {
    fail(
      "SIGNER_CERTIFICATE_PROFILE_INVALID",
      "The signer certificate keyUsage must be limited to digitalSignature and/or contentCommitment.",
    );
  }

  const details = x509.publicKey.asymmetricKeyDetails ?? {};
  if (
    ["rsa", "rsa-pss"].includes(x509.publicKey.asymmetricKeyType) &&
    Number(details.modulusLength ?? 0) < 2048
  ) {
    fail(
      "SIGNER_KEY_TOO_WEAK",
      "The timestamp signer RSA key is below the 2048-bit minimum.",
    );
  }
}

function assertCertificateValidAt(x509, date, role) {
  const checkedAt = date.valueOf();
  const notBefore = Date.parse(x509.validFrom);
  const notAfter = Date.parse(x509.validTo);
  if (
    !Number.isFinite(checkedAt) ||
    !Number.isFinite(notBefore) ||
    !Number.isFinite(notAfter) ||
    checkedAt < notBefore ||
    checkedAt > notAfter
  ) {
    fail(
      "CERTIFICATE_NOT_VALID_AT_GENTIME",
      `The ${role} certificate was not valid at the RFC 3161 genTime.`,
    );
  }
}

function parsePssParameters(algorithmIdentifier, digestAlgorithm) {
  if (!algorithmIdentifier.algorithmParams) {
    fail("UNSUPPORTED_SIGNATURE_ALGORITHM", "RSASSA-PSS parameters are required.");
  }
  let parameters;
  try {
    parameters = new RSASSAPSSParams({
      schema: algorithmIdentifier.algorithmParams,
    });
  } catch {
    fail("UNSUPPORTED_SIGNATURE_ALGORITHM", "RSASSA-PSS parameters are malformed.");
  }
  const pssHash = hashAlgorithmForOid(
    parameters.hashAlgorithm.algorithmId,
    "The RSASSA-PSS signature",
  );
  if (
    pssHash.nodeName !== digestAlgorithm.nodeName ||
    parameters.maskGenAlgorithm.algorithmId !== MGF1_OID ||
    parameters.trailerField !== 1 ||
    parameters.saltLength < pssHash.digestBytes
  ) {
    fail(
      "UNSUPPORTED_SIGNATURE_ALGORITHM",
      "The RSASSA-PSS parameters do not meet the SiteSealed verification profile.",
    );
  }
  let mgfHash;
  try {
    mgfHash = new AlgorithmIdentifier({
      schema: parameters.maskGenAlgorithm.algorithmParams,
    });
  } catch {
    fail("UNSUPPORTED_SIGNATURE_ALGORITHM", "The RSASSA-PSS MGF1 parameters are malformed.");
  }
  if (mgfHash.algorithmId !== parameters.hashAlgorithm.algorithmId) {
    fail(
      "UNSUPPORTED_SIGNATURE_ALGORITHM",
      "The RSASSA-PSS MGF1 hash must match the signature hash.",
    );
  }
  return { saltLength: parameters.saltLength, displayName: `RSA_PSS_${pssHash.displayName}` };
}

function verifyCmsSignature({ signerInfo, signerX509, signedBytes, signature }) {
  const digestAlgorithm = hashAlgorithmForOid(
    signerInfo.digestAlgorithm.algorithmId,
    "The CMS SignerInfo",
  );
  const signatureOid = signerInfo.signatureAlgorithm.algorithmId;
  let signatureProfile = SIGNATURE_ALGORITHMS.get(signatureOid);
  let keyOptions = signerX509.publicKey;
  let displayName;

  if (signatureOid === RSA_ENCRYPTION_OID) {
    signatureProfile = {
      kind: "rsa-pkcs1",
      hashOid: signerInfo.digestAlgorithm.algorithmId,
      displayName: `RSA_PKCS1_${digestAlgorithm.displayName}`,
    };
  } else if (signatureOid === RSA_PSS_OID) {
    const pss = parsePssParameters(
      signerInfo.signatureAlgorithm,
      digestAlgorithm,
    );
    signatureProfile = {
      kind: "rsa-pss",
      hashOid: signerInfo.digestAlgorithm.algorithmId,
      displayName: pss.displayName,
      saltLength: pss.saltLength,
    };
  }
  if (!signatureProfile || signatureProfile.hashOid !== signerInfo.digestAlgorithm.algorithmId) {
    fail(
      "UNSUPPORTED_SIGNATURE_ALGORITHM",
      "The CMS signature algorithm is unsupported or inconsistent with its digest algorithm.",
    );
  }

  if (signatureProfile.kind === "rsa-pkcs1") {
    keyOptions = {
      key: signerX509.publicKey,
      padding: constants.RSA_PKCS1_PADDING,
    };
  } else if (signatureProfile.kind === "rsa-pss") {
    keyOptions = {
      key: signerX509.publicKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: signatureProfile.saltLength,
    };
  }
  displayName = signatureProfile.displayName;

  const valid = verifySignature(
    digestAlgorithm.nodeName,
    signedBytes,
    keyOptions,
    signature,
  );
  if (!valid) {
    fail("CMS_SIGNATURE_INVALID", "The RFC 3161 CMS signature is invalid.");
  }
  return {
    digestAlgorithm,
    signatureAlgorithm: displayName,
  };
}

function parseToken(token) {
  const bytes = Buffer.from(token ?? []);
  if (bytes.length < 16 || bytes.length > MAX_TOKEN_BYTES) {
    fail("TOKEN_SIZE_INVALID", "The RFC 3161 token size is invalid.");
  }
  let asn1;
  try {
    asn1 = fromBER(bytes);
  } catch {
    fail("TOKEN_ASN1_INVALID", "The RFC 3161 token is not valid DER/BER.");
  }
  if (asn1.offset !== bytes.length) {
    fail(
      "TOKEN_ASN1_INVALID",
      "The RFC 3161 token contains malformed or trailing ASN.1 data.",
    );
  }
  let contentInfo;
  let signedData;
  try {
    contentInfo = new ContentInfo({ schema: asn1.result });
    if (contentInfo.contentType !== CMS_SIGNED_DATA_OID) {
      fail("TOKEN_CONTENT_TYPE_INVALID", "The RFC 3161 token is not CMS SignedData.");
    }
    signedData = new SignedData({ schema: contentInfo.content });
  } catch (error) {
    if (error instanceof Rfc3161VerificationError) throw error;
    fail("TOKEN_CMS_INVALID", "The RFC 3161 CMS SignedData structure is malformed.");
  }
  if (
    signedData.version !== 3 ||
    signedData.signerInfos.length !== 1 ||
    signedData.encapContentInfo.eContentType !== TST_INFO_OID ||
    !signedData.encapContentInfo.eContent
  ) {
    fail(
      "TOKEN_CMS_PROFILE_INVALID",
      "The token must contain one CMS signer and encapsulated TSTInfo content.",
    );
  }
  const tstInfoBytes = Buffer.from(
    signedData.encapContentInfo.eContent.getValue(),
  );
  let tstAsn1;
  let tstInfo;
  try {
    tstAsn1 = fromBER(tstInfoBytes);
    if (tstAsn1.offset !== tstInfoBytes.length) throw new Error("Trailing TSTInfo data");
    tstInfo = new TSTInfo({ schema: tstAsn1.result });
  } catch {
    fail("TSTINFO_INVALID", "The RFC 3161 TSTInfo structure is malformed.");
  }
  if (tstInfo.version !== 1) {
    fail("TSTINFO_VERSION_INVALID", "Only RFC 3161 TSTInfo version 1 is accepted.");
  }
  return { bytes, signedData, tstInfo, tstInfoBytes };
}

export async function verifyRfc3161Token({
  token,
  expectedDigest,
  expectedSerialNumber = null,
  expectedCertifiedAt = null,
  expectedPolicyId = null,
  trustStore = null,
} = {}) {
  const digest = String(expectedDigest ?? "").trim().toLowerCase();
  if (!SHA256_PATTERN.test(digest)) {
    fail("INVALID_EXPECTED_VALUE", "expectedDigest must be a SHA-256 digest.");
  }
  const parsed = parseToken(token);
  const { bytes, signedData, tstInfo, tstInfoBytes } = parsed;
  const signerInfo = signedData.signerInfos[0];
  if (
    signedData.digestAlgorithms.length !== 1 ||
    !equalBytes(
      algorithmIdentifierDer(signedData.digestAlgorithms[0]),
      algorithmIdentifierDer(signerInfo.digestAlgorithm),
    )
  ) {
    fail(
      "CMS_DIGEST_ALGORITHM_SET_INVALID",
      "The CMS digestAlgorithms set does not match its sole SignerInfo.",
    );
  }
  const attributes = signerInfo.signedAttrs?.attributes;
  if (!Array.isArray(attributes)) {
    fail("SIGNED_ATTRIBUTES_MISSING", "The RFC 3161 CMS signer has no signed attributes.");
  }

  const contentType = requireSingleAttribute(
    attributes,
    CONTENT_TYPE_ATTRIBUTE_OID,
    "contentType",
  );
  if (contentType.valueBlock.toString() !== TST_INFO_OID) {
    fail(
      "SIGNED_CONTENT_TYPE_MISMATCH",
      "The signed CMS contentType does not identify TSTInfo.",
    );
  }
  const messageDigest = requireSingleAttribute(
    attributes,
    MESSAGE_DIGEST_ATTRIBUTE_OID,
    "messageDigest",
  );
  if (!(messageDigest instanceof OctetString)) {
    fail(
      "SIGNED_ATTRIBUTE_INVALID",
      "The CMS messageDigest signed attribute must be an OCTET STRING.",
    );
  }
  const cmsDigestAlgorithm = hashAlgorithmForOid(
    signerInfo.digestAlgorithm.algorithmId,
    "The CMS SignerInfo",
  );
  const calculatedContentDigest = createHash(cmsDigestAlgorithm.nodeName)
    .update(tstInfoBytes)
    .digest();
  if (!equalBytes(calculatedContentDigest, messageDigest.valueBlock.valueHexView)) {
    fail(
      "CMS_CONTENT_DIGEST_MISMATCH",
      "The signed CMS messageDigest does not match the encapsulated TSTInfo.",
    );
  }

  const algorithmProtection = verifyCmsAlgorithmProtection(
    optionalSingleAttribute(
      attributes,
      CMS_ALGORITHM_PROTECTION_ATTRIBUTE_OID,
      "cmsAlgorithmProtection",
    ),
    signerInfo,
  );
  const signerCertificate = await findSignerCertificate(signedData, signerInfo);
  const signerRaw = Buffer.from(signerCertificate.toSchema(true).toBER(false));
  let signerX509;
  try {
    signerX509 = new X509Certificate(signerRaw);
  } catch {
    fail("SIGNER_CERTIFICATE_INVALID", "The embedded CMS signer certificate is malformed.");
  }
  assertTimestampSignerProfile(signerCertificate, signerX509);

  const signingCertificate = verifySigningCertificateV2(
    requireSingleAttribute(
      attributes,
      SIGNING_CERTIFICATE_V2_ATTRIBUTE_OID,
      "signingCertificateV2",
    ),
    signerRaw,
  );

  const signedBytes = Buffer.from(signerInfo.signedAttrs.encodedValue);
  if (signedBytes[0] !== 0x31) {
    fail(
      "SIGNED_ATTRIBUTES_ENCODING_INVALID",
      "The CMS signed attributes are not in the required DER SET encoding.",
    );
  }
  const signature = Buffer.from(signerInfo.signature.valueBlock.valueHexView);
  const cmsSignature = verifyCmsSignature({
    signerInfo,
    signerX509,
    signedBytes,
    signature,
  });

  const imprintAlgorithm = hashAlgorithmForOid(
    tstInfo.messageImprint.hashAlgorithm.algorithmId,
    "The RFC 3161 message imprint",
  );
  if (imprintAlgorithm.displayName !== "SHA256") {
    fail(
      "MESSAGE_IMPRINT_ALGORITHM_INVALID",
      "The Evidency RFC 3161 message imprint must use SHA-256.",
    );
  }
  const tokenDigest = Buffer.from(
    tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView,
  ).toString("hex");
  if (tokenDigest !== digest) {
    fail(
      "MESSAGE_IMPRINT_MISMATCH",
      "The RFC 3161 message imprint does not match the SiteSealed evidence digest.",
    );
  }

  const serialNumber = integerHex(tstInfo.serialNumber);
  const certifiedAt = tstInfo.genTime.toISOString();
  const tsaPolicyId = String(tstInfo.policy ?? "");
  if (!OID_PATTERN.test(tsaPolicyId)) {
    fail("TSTINFO_POLICY_INVALID", "The RFC 3161 policy identifier is invalid.");
  }
  if (
    expectedSerialNumber !== null &&
    serialNumber !== canonicalSerial(expectedSerialNumber, "provider serial number")
  ) {
    fail("PROVIDER_SERIAL_MISMATCH", "The provider serial number does not match TSTInfo.");
  }
  if (
    expectedCertifiedAt !== null &&
    new Date(expectedCertifiedAt).valueOf() !== tstInfo.genTime.valueOf()
  ) {
    fail("PROVIDER_TIME_MISMATCH", "The provider timestamp does not match TSTInfo genTime.");
  }
  if (expectedPolicyId !== null && String(expectedPolicyId) !== tsaPolicyId) {
    fail("PROVIDER_POLICY_MISMATCH", "The provider policy identifier does not match TSTInfo.");
  }

  const pinnedTrust = trustStore ?? getDefaultTrustStore();
  assertCertificateValidAt(signerX509, tstInfo.genTime, "timestamp signer");
  assertCertificateValidAt(
    pinnedTrust.timestampCa.x509,
    tstInfo.genTime,
    "timestamp CA",
  );
  assertCertificateValidAt(pinnedTrust.root.x509, tstInfo.genTime, "root CA");
  if (
    !signerX509.checkIssued(pinnedTrust.timestampCa.x509) ||
    !signerX509.verify(pinnedTrust.timestampCa.x509.publicKey)
  ) {
    fail(
      "CERTIFICATE_CHAIN_INVALID",
      "The timestamp signer certificate does not validate to the pinned timestamp CA.",
    );
  }

  const chainEngine = new CertificateChainValidationEngine({
    certs: [signerCertificate, pinnedTrust.timestampCa.pkijs],
    trustedCerts: [pinnedTrust.root.pkijs],
    checkDate: tstInfo.genTime,
  });
  let chainResult;
  try {
    chainResult = await chainEngine.verify({ passedWhenNotRevValues: true });
  } catch {
    fail(
      "CERTIFICATE_CHAIN_INVALID",
      "The timestamp certificate path could not be validated.",
    );
  }
  if (!chainResult.result) {
    fail(
      "CERTIFICATE_CHAIN_INVALID",
      "The timestamp certificate path is invalid.",
    );
  }
  const pathFingerprints = new Set(
    (chainResult.certificatePath ?? []).map((certificate) =>
      sha256(Buffer.from(certificate.toSchema(true).toBER(false))),
    ),
  );
  if (
    !pathFingerprints.has(pinnedTrust.timestampCa.fingerprint) ||
    !pathFingerprints.has(pinnedTrust.root.fingerprint)
  ) {
    fail(
      "CERTIFICATE_CHAIN_INVALID",
      "The validated certificate path does not terminate at the pinned sandbox root.",
    );
  }

  return {
    validatorVersion: RFC3161_VALIDATOR_VERSION,
    signatureVerification: "VALID",
    certificateChainVerification: "VALID_TO_PINNED_SANDBOX_ROOT",
    signingCertificateVerification: signingCertificate.status,
    signingCertificateHashAlgorithm: signingCertificate.hashAlgorithm,
    cmsAlgorithmProtection: algorithmProtection,
    revocationVerification: "NOT_CHECKED",
    responseValidation: "RFC3161_CMS_SIGNATURE_CHAIN_AND_DIGEST_VALID",
    hashAlgorithm: imprintAlgorithm.displayName,
    hashedMessage: tokenDigest,
    serialNumber,
    certifiedAt,
    tsaPolicyId,
    tokenSha256: sha256(bytes),
    cmsDigestAlgorithm: cmsSignature.digestAlgorithm.displayName,
    cmsSignatureAlgorithm: cmsSignature.signatureAlgorithm,
    signerCertificateSha256: sha256(signerRaw),
    signerCertificateSubject: signerX509.subject,
    signerCertificateIssuer: signerX509.issuer,
    signerCertificateValidFrom: new Date(signerX509.validFrom).toISOString(),
    signerCertificateValidTo: new Date(signerX509.validTo).toISOString(),
    trustAnchorSha256: pinnedTrust.root.fingerprint,
    trustAnchorSubject: pinnedTrust.root.x509.subject,
    certificatePathLength: 3,
  };
}
