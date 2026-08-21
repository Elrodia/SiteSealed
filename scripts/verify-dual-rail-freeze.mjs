import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const expected = new Map([
  [
    ".env.example",
    "bd56992bb7bce198c1e62e8d1bf5c2061c9dede6fb6b766b8dd2bcc81b547467",
  ],
  [
    "server/evidency.js",
    "04c4b2916e03e494cb8025b311881e4435f74e5ff528a2eedd357dbe9b1969b0",
  ],
  [
    "server/ethereum.js",
    "e2bf70ea93dcd64ef13a0d1d168a1c472dd264f7cae89c364413d61b89d142c8",
  ],
  [
    "server/rails-worker.js",
    "9c542f916d0d85a08e7a955c126357ae1fd830416373589c7a2494eff5a4d71c",
  ],
  [
    "railway.json",
    "614b90a480632cc7b88cc271d31278e1104846d1b64406c9278b9d0a36fc8c5e",
  ],
  [
    "railway.rails.json",
    "1d6d0cfee4191048305a4bb40a8269580e5d4f41e4035366f532b27031d1164e",
  ],
]);

let failed = false;
for (const [fileName, expectedSha256] of expected) {
  const bytes = await readFile(new URL(`../${fileName}`, import.meta.url));
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  const state = actualSha256 === expectedSha256 ? "PASS" : "FAIL";
  console.log(`${state} ${fileName} ${actualSha256}`);
  failed ||= state === "FAIL";
}

if (failed) {
  throw new Error(
    "The frozen Evidency/Ethereum dual-rail implementation or Railway service configuration changed.",
  );
}

console.log("Dual-rail freeze verified: the Evidency/Ethereum implementation and Railway rail settings remain frozen; the approved environment template is unchanged.");
