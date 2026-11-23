import { X509Certificate, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { Certificate } from "pkijs";

const environments = new Set(["SANDBOX", "PRODUCTION"]);
const stores = new WeakMap();
const trustDirectory = new URL("./trust/", import.meta.url);
const isoUtc = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/;
const supportedFields = new Set(["id", "parentId", "environment", "role", "status", "file", "sha256", "retireAt"]);

export class Rfc3161VerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "Rfc3161VerificationError";
    this.code = code;
  }
}
function reject(message, code = "TRUST_MANIFEST_INVALID") {
  throw new Rfc3161VerificationError(code, message);
}
function strictUtc(value) {
  if (typeof value !== "string" || !isoUtc.test(value)) return NaN;
  const ms = Date.parse(value);
  return Number.isFinite(ms) && new Date(ms).toISOString() === value.replace(/(\d\d:\d\d:\d\d)Z$/, "$1.000Z") ? ms : NaN;
}
function digest(raw) {
  return createHash("sha256").update(raw).digest("hex");
}
export function createTrustPolicy(manifest, {
  readCertificate = (name) => readFileSync(new URL(name, trustDirectory)),
} = {}) {
  if (manifest?.schemaVersion !== 1 || !Number.isSafeInteger(manifest.revision) ||
      manifest.revision < 1 || !Array.isArray(manifest.certificates) ||
      Object.keys(manifest).some((k) => !["schemaVersion","revision","certificates"].includes(k))) {
    reject("Unsupported or invalid timestamp trust manifest.");
  }
  const ids = new Map();
  const pins = new Map();
  for (const entry of manifest.certificates) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) ||
        Object.keys(entry).some((k) => !supportedFields.has(k)) ||
        typeof entry.id !== "string" || !/^[a-zA-Z0-9_-]{1,96}$/.test(entry.id) ||
        !environments.has(entry.environment) ||
        !["root","issuer","signer"].includes(entry.role) ||
        !["active","retiring","revoked"].includes(entry.status) ||
        typeof entry.file !== "string" || !/^[a-zA-Z0-9_-]+\.(pem|der)$/.test(entry.file) ||
        typeof entry.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(entry.sha256) ||
        ids.has(entry.id) || pins.has(entry.sha256) ||
        (entry.role === "root" ? Object.hasOwn(entry, "parentId") : typeof entry.parentId !== "string") ||
        (entry.status === "retiring" ? !Number.isFinite(strictUtc(entry.retireAt)) : Object.hasOwn(entry, "retireAt"))) {
      reject("Invalid, duplicate or ambiguous timestamp trust manifest entry.");
    }
    let x509;
    try { x509 = new X509Certificate(readCertificate(entry.file)); }
    catch { reject("Pinned certificate unreadable: " + entry.id, "TRUST_BUNDLE_INVALID"); }
    const fingerprint = digest(x509.raw);
    if (fingerprint !== entry.sha256) reject("Pinned certificate fingerprint mismatch: " + entry.id, "TRUST_BUNDLE_INTEGRITY_FAILED");
    if ((entry.role !== "signer") !== x509.ca) reject("Pinned certificate has the wrong CA role: " + entry.id);
    const cert = Object.freeze({ ...entry, fingerprint, x509, pkijs: Certificate.fromBER(x509.raw),
      from: Date.parse(x509.validFrom), to: Date.parse(x509.validTo), cutoff: strictUtc(entry.retireAt) });
    ids.set(cert.id, cert);
    pins.set(cert.sha256, cert);
  }
  for (const cert of ids.values()) {
    const parent = cert.role === "root" ? cert : ids.get(cert.parentId);
    const expectedRole = cert.role === "signer" ? "issuer" : "root";
    if (!parent || parent.role !== expectedRole || parent.environment !== cert.environment ||
        !cert.x509.checkIssued(parent.x509) || !cert.x509.verify(parent.x509.publicKey)) {
      reject("Pinned certificate does not validate to its declared parent: " + cert.id, "TRUST_BUNDLE_INVALID");
    }
  }
  const policy = Object.freeze({ revision: manifest.revision });
  stores.set(policy, {ids, pins});
  return policy;
}

const installedBytes = readFileSync(new URL("anchors.v1.json", trustDirectory));
const installed = createTrustPolicy(JSON.parse(installedBytes.toString("utf8")));
export const TRUST_MANIFEST_REVISION = installed.revision;
export const TRUST_MANIFEST_SHA256 = digest(installedBytes);
function internal(policy) {
  const store = stores.get(policy);
  if (!store) reject("Unrecognized trust policy.");
  return store;
}
function chainFor(ids, signer) {
  const issuer = ids.get(signer.parentId);
  return [signer, issuer, ids.get(issuer.parentId)];
}

export function selectTrustPath({trustStore = null, environment, signerSha256, usage, at}) {
  const policy = trustStore ?? installed;
  const {pins, ids} = internal(policy);
  if (!environments.has(environment) || !["issuance","historical"].includes(usage)) reject("Invalid trust environment or verification usage.");
  const signer = pins.get(signerSha256);
  if (!signer || signer.role !== "signer" || signer.environment !== environment) {
    reject("Timestamp signer is not approved for this environment.", "UNTRUSTED_TIMESTAMP_SIGNER");
  }
  const path = chainFor(ids, signer);
  if (path.some((c) => c.status === "revoked")) {
    reject("The signer or one of its issuers is locally revoked.", "TRUST_PATH_REVOKED");
  }
  if (path.some((c) => c.status === "retiring" && (usage !== "historical" || !(at < c.cutoff)))) {
    reject("A retiring certificate cannot authorize this timestamp.", "TRUST_PATH_RETIRING");
  }
  if (!Number.isFinite(at) || path.some((c) => at < c.from || at > c.to)) {
    reject("A certificate was not valid at the RFC 3161 genTime.", "CERTIFICATE_NOT_VALID_AT_GENTIME");
  }
  return { signer, timestampCa: path[1], root: path[2], revision: policy.revision };
}

// Re-evaluates pins/status for a previously verified proof; does not replace CMS verification.
export function isStoredTimestampTrusted(proof, {trustStore = null, usage = "historical"} = {}) {
  if (!proof || !environments.has(proof.environment)) return false;
  const at = strictUtc(proof.certifiedAt);
  try {
    const path = selectTrustPath({trustStore, usage, environment: proof.environment, at,
      signerSha256: proof.signerCertificateSha256});
    return path.root.fingerprint === proof.trustAnchorSha256;
  } catch { return false; }
}

export function getTrustManifestHealth({trustStore = null, environment = "SANDBOX", now = Date.now()} = {}) {
  const stamp = new Date(now).valueOf();
  if (!environments.has(environment) || !Number.isFinite(stamp)) reject("Invalid trust health parameters.");
  const policy = trustStore ?? installed;
  const { ids } = internal(policy);
  const certs = [...ids.values()].filter((c) => c.environment === environment);
  const activePaths = certs.filter((c) => c.role === "signer" &&
    chainFor(ids, c).every((a) => a.status === "active" && a.from <= stamp && a.to >= stamp)).length;
  const expiring = certs.filter((c) => c.status !== "revoked" && c.to - stamp < 90 * 86_400_000)
    .map((c) => ({id:c.id, role:c.role, notAfter:new Date(c.to).toISOString(), status:c.status,
      daysRemaining:Math.floor((c.to - stamp) / 86_400_000)}));
  return {revision:policy.revision, environment, activePaths, expiring,
    status:!activePaths ? "unavailable" : expiring.length ? "warning" : "ok"};
}
