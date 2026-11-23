import assert from "node:assert/strict";
import { createHash, webcrypto, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { BitString, Integer, OctetString, Sequence, Utf8String } from "asn1js";
import {
  Attribute, AttributeTypeAndValue, BasicConstraints, Certificate, ContentInfo, ExtKeyUsage,
  Extension, IssuerAndSerialNumber, SignedAndUnsignedAttributes, SignedData, SignerInfo,
} from "pkijs";
import {
  createTrustPolicy, getTrustManifestHealth, isStoredTimestampTrusted, verifyRfc3161Token,
} from "./rfc3161.js";

const trustDir = new URL("./trust/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("anchors.v1.json", trustDir), "utf8"));
const fixture = JSON.parse(readFileSync(new URL("./fixtures/evidency-sandbox-token-20260812.json", import.meta.url), "utf8"));
const token = Buffer.from(fixture.tokenBase64, "base64");
const genTime = Date.parse(fixture.certifiedAt);
const shift = (delta) => new Date(genTime + delta).toISOString();
const read = (file) => readFileSync(new URL(file, trustDir));
const verify = (trustStore, options = {}) => verifyRfc3161Token({
  token, expectedDigest: fixture.evidenceDigest, trustStore, ...options,
});
function amend(role, updates) {
  const copy = structuredClone(manifest);
  Object.assign(copy.certificates.find((cert) => cert.role === role), updates);
  return createTrustPolicy(copy);
}

test("local revocation of signer, issuing CA or root rejects even historical tokens", async () => {
  const proof = { ...(await verify(createTrustPolicy(manifest))), environment: "SANDBOX" };
  assert.equal(isStoredTimestampTrusted(proof), true);
  for (const role of ["root", "issuer", "signer"]) {
    const trustStore = amend(role, { status: "revoked" });
    await assert.rejects(verify(trustStore));
    await assert.rejects(verify(trustStore, { usage: "historical" }));
    assert.equal(isStoredTimestampTrusted(proof, { trustStore }), false);
  }
});

test("retiring allows only historical tokens strictly before the cutoff; fresh intake fails", async () => {
  for (const role of ["root", "issuer", "signer"]) {
    const beforeCutoff = amend(role, { status: "retiring", retireAt: shift(1000) });
    await assert.rejects(verify(beforeCutoff));
    const proof = await verify(beforeCutoff, { usage: "historical" });
    assert.equal(proof.tokenSha256, fixture.tokenSha256);
    const atCutoff = amend(role, { status: "retiring", retireAt: shift(0) });
    await assert.rejects(verify(atCutoff, { usage: "historical" }));
    assert.equal(isStoredTimestampTrusted({ ...proof, environment: "SANDBOX" }, { trustStore: atCutoff }), false);
  }
});

test("an embedded signer is not automatically trusted; sandbox paths do not cross into production", async () => {
  const policy = createTrustPolicy(manifest);
  const proof = await verify(policy);
  const noSigner = structuredClone(manifest);
  noSigner.certificates = noSigner.certificates.filter((entry) => entry.sha256 !== proof.signerCertificateSha256);
  await assert.rejects(verify(createTrustPolicy(noSigner)));
  await assert.rejects(verify(policy, { environment: "PRODUCTION" }));
  assert.equal(isStoredTimestampTrusted({ ...proof, environment: "PRODUCTION" }, { trustStore: policy }), false);
  assert.equal(isStoredTimestampTrusted({ ...proof, environment: "SANDBOX", trustAnchorSha256: "f".repeat(64) }, { trustStore: policy }), false);
  assert.equal(getTrustManifestHealth({ environment: "PRODUCTION", trustStore: policy, now: genTime }).status, "unavailable");
});

test("rejects ambiguous IDs, duplicate DER pins, wrong hashes, and malformed status or topology", () => {
  const changes = [
    (m) => { m.schemaVersion = 999; },
    (m) => { m.certificates[1].id = m.certificates[0].id; },
    (m) => { m.certificates.push({ ...m.certificates[0], id: "duplicate-fingerprint" }); },
    (m) => { m.certificates[0].sha256 = "0".repeat(64); },
    (m) => { m.certificates[0].status = "disabled"; },
    (m) => { m.certificates[0].status = "retiring"; },
    (m) => { m.certificates.find((c) => c.role === "signer").parentId = "missing"; },
    (m) => { m.certificates.find((c) => c.role === "issuer").environment = "PRODUCTION"; },
    (m) => { m.certificates[0].file = "../package.json"; },
  ];
  for (const change of changes) {
    const broken = structuredClone(manifest);
    change(broken);
    assert.throws(() => createTrustPolicy(broken));
  }
});

test("health computes expiry from pinned X.509 material and warns within 90 days", () => {
  const signer = manifest.certificates.find((cert) => cert.role === "signer");
  const notAfter = Date.parse(new X509Certificate(read(signer.file)).validTo);
  const day = 86_400_000;
  const trustStore = createTrustPolicy(manifest);
  const earlier = getTrustManifestHealth({ trustStore, now: notAfter - 91 * day });
  assert.equal(earlier.expiring.some((cert) => cert.id === signer.id), false);
  const soon = getTrustManifestHealth({ trustStore, now: notAfter - 89 * day });
  assert.equal(soon.status, "warning");
  assert.equal(soon.expiring.some((cert) => cert.id === signer.id), true);
});

// An independent synthetic hierarchy exists only in this test process. No test
// key, CA, or certificate is written to disk or admitted to the release policy.
async function makeTestCert(role, parent = null) {
  const key = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const certificate = new Certificate();
  certificate.version = 2;
  certificate.serialNumber = new Integer({ value: { root: 101, issuer: 102, signer: 103 }[role] });
  certificate.subject.typesAndValues = [
    new AttributeTypeAndValue({ type: "2.5.4.3", value: new Utf8String({ value: `SiteSealed test ${role}` }) }),
  ];
  certificate.issuer = parent?.certificate.subject ?? certificate.subject;
  certificate.notBefore.value = new Date("2020-01-01T00:00:00Z");
  certificate.notAfter.value = new Date("2040-01-01T00:00:00Z");
  const ca = role !== "signer";
  const extension = (extnID, value) => new Extension({ extnID, critical: true, extnValue: value.toBER(false) });
  certificate.extensions = [
    extension("2.5.29.19", new BasicConstraints({ cA: ca }).toSchema()),
    extension("2.5.29.15", new BitString({ unusedBits: ca ? 1 : 7, valueHex: Uint8Array.of(ca ? 6 : 128).buffer })),
    ...(!ca ? [extension("2.5.29.37", new ExtKeyUsage({ keyPurposes: ["1.3.6.1.5.5.7.3.8"] }).toSchema())] : []),
  ];
  await certificate.subjectPublicKeyInfo.importKey(key.publicKey);
  await certificate.sign(parent?.key.privateKey ?? key.privateKey, "SHA-256");
  const raw = Buffer.from(certificate.toSchema(true).toBER(false));
  return {
    key, certificate, pem: new X509Certificate(raw).toString(),
    entry: { id: `test-${role}`, role, environment: "SANDBOX", status: "active",
      ...(parent ? { parentId: parent.entry.id } : {}), file: `test-${role}.pem`,
      sha256: createHash("sha256").update(raw).digest("hex") },
  };
}

// Keep the fixture's TSTInfo and its contentType/messageDigest attributes, but
// issue a separate token under our ephemeral signer, bound by its own ESSCertIDv2.
async function signTestToken(signer) {
  const info = ContentInfo.fromBER(token);
  const data = new SignedData({ schema: info.content });
  const oldAttrs = data.signerInfos[0].signedAttrs.attributes;
  const seq = (...value) => new Sequence({ value });
  data.certificates = [signer.certificate];
  data.digestAlgorithms = [];
  data.signerInfos = [new SignerInfo({
    version: 1,
    sid: new IssuerAndSerialNumber({ issuer: signer.certificate.issuer, serialNumber: signer.certificate.serialNumber }),
    signedAttrs: new SignedAndUnsignedAttributes({ type: 0, attributes: [
      ...oldAttrs.filter((a) => ["1.2.840.113549.1.9.3", "1.2.840.113549.1.9.4"].includes(a.type)),
      new Attribute({ type: "1.2.840.113549.1.9.16.2.47", values: [
        seq(seq(seq(new OctetString({ valueHex: Uint8Array.from(Buffer.from(signer.entry.sha256, "hex")).buffer })))),
      ] }),
    ] }),
  })];
  await data.sign(signer.key.privateKey, 0, "SHA-512");
  info.content = data.toSchema();
  return Buffer.from(info.toSchema().toBER(false));
}

test("overlapping active chains resolve by signer and issuer, not manifest order", async () => {
  const root = await makeTestCert("root");
  const issuer = await makeTestCert("issuer", root);
  const signer = await makeTestCert("signer", issuer);
  const alternates = [root, issuer, signer];
  const alternateToken = await signTestToken(signer);
  const readCertificate = (file) => alternates.find((cert) => cert.entry.file === file)?.pem ?? read(file);
  for (const first of [true, false]) {
    const copy = structuredClone(manifest);
    const extra = alternates.map((cert) => cert.entry);
    copy.certificates = first ? [...extra, ...copy.certificates] : [...copy.certificates, ...extra];
    const trustStore = createTrustPolicy(copy, { readCertificate });
    const proof = await verify(trustStore);
    assert.equal(proof.tokenSha256, fixture.tokenSha256);
    assert.notEqual(proof.trustAnchorSha256, root.entry.sha256);
    const otherProof = await verify(trustStore, { token: alternateToken });
    assert.equal(otherProof.trustAnchorSha256, root.entry.sha256);
    assert.equal(otherProof.signerCertificateSha256, signer.entry.sha256);
    assert.equal(getTrustManifestHealth({ trustStore, now: genTime }).activePaths, 2);
    assert.equal(isStoredTimestampTrusted({ ...proof, environment: "SANDBOX",
      trustAnchorSha256: root.entry.sha256 }, { trustStore }), false);
  }
});
