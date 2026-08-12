import { loadEnvFile } from "node:process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));

try {
  loadEnvFile(path.resolve(directory, "../.env"));
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}

