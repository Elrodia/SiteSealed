import { spawn } from "node:child_process";

const forwardedArgs = process.argv.slice(2);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const processes = [
  spawn(npmCommand, ["run", "dev", "--workspace", "server"], {
    stdio: "inherit",
    env: process.env,
  }),
  spawn(
    npmCommand,
    [
      "run",
      "dev",
      "--workspace",
      "client",
      ...(forwardedArgs.length ? ["--", ...forwardedArgs] : []),
    ],
    {
      stdio: "inherit",
      env: process.env,
    },
  ),
];

let shuttingDown = false;

function stopAll(signal = "SIGTERM") {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const process of processes) {
    if (!process.killed) process.kill(signal);
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => stopAll(signal));
}

for (const child of processes) {
  child.once("error", (error) => {
    console.error("Unable to start the development process", error);
    stopAll();
    process.exit(1);
  });

  child.once("exit", (code, signal) => {
    if (shuttingDown) return;
    stopAll(signal ?? "SIGTERM");
    process.exit(code ?? 1);
  });
}
