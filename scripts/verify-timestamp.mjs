import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  Rfc3161VerificationError,
  verifyRfc3161Token,
} from "../server/rfc3161.js";

function argumentsByName(values) {
  const parsed = new Map();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(
        "Usage: npm run verify:timestamp -- --token <file.tsr> --digest <sha256> [--serial <hex>] [--time <ISO8601>] [--policy <oid>]",
      );
    }
    if (parsed.has(name)) throw new Error(`Duplicate argument: ${name}`);
    parsed.set(name, value);
  }
  return parsed;
}

try {
  const args = argumentsByName(process.argv.slice(2));
  const tokenPath = args.get("--token");
  const digest = args.get("--digest");
  if (!tokenPath || !digest) {
    throw new Error(
      "Both --token and --digest are required. The digest is the SiteSealed evidenceDigest, not the file SHA-256.",
    );
  }
  const token = await readFile(resolve(tokenPath));
  const verification = await verifyRfc3161Token({
    token,
    expectedDigest: digest,
    expectedSerialNumber: args.get("--serial") ?? null,
    expectedCertifiedAt: args.get("--time") ?? null,
    expectedPolicyId: args.get("--policy") ?? null,
  });
  process.stdout.write(
    `${JSON.stringify({ ok: true, verification }, null, 2)}\n`,
  );
} catch (error) {
  process.stderr.write(
    `${JSON.stringify(
      {
        ok: false,
        code:
          error instanceof Rfc3161VerificationError
            ? error.code
            : "VERIFIER_USAGE_OR_IO_ERROR",
        message: error.message,
      },
      null,
      2,
    )}\n`,
  );
  process.exitCode = 1;
}
