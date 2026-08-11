import { spawn } from "node:child_process";

const forwardedArgs = process.argv.slice(2);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const npmArgs = forwardedArgs.length
  ? ["run", "dev", "--workspace", "client", "--", ...forwardedArgs]
  : ["run", "dev:full"];

const child = spawn(npmCommand, npmArgs, {
  stdio: "inherit",
  env: process.env,
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => child.kill(signal));
}

child.once("error", (error) => {
  console.error("Unable to start the development process", error);
  process.exit(1);
});

child.once("exit", (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
