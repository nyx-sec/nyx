// Negative regression: shell-arrays whose payload is a static literal must
// not fire (no taint can reach a constant), and array literals whose first
// element is not a known shell must not fire even with taint in element 2.
// Also locks in the four FPs documented in the recent EXCLUDES carve-out:
// the canonical Dockerode `container.exec({ Cmd: argv })` form, an opaque
// untainted-array variable, and `execSync(cmd, { env: process.env })`.
import Docker from "dockerode";

const docker = new Docker({ socketPath: "/var/run/docker.sock" });

async function inert(_id: string, _cmd: string[]): Promise<void> {}

export async function staticShellPayload(req: any): Promise<void> {
  // Constant payload — the third element is a literal string.  Even though
  // the array shape matches [bash, -c, *], no identifiers exist in element
  // 2 so the detector emits no sink filter.
  await inert("c", ["bash", "-c", "ls -la /app"]);
}

export async function nonShellArray(req: any): Promise<void> {
  const tainted = req.query.cmd;
  // First element is not a known shell.  Detector should not match even
  // though element 2 carries taint.
  await inert("c", ["ls", "-la", tainted]);
}

export async function dockerodeCanonicalArgv(
  containerId: string,
  req: any
): Promise<void> {
  const container = docker.getContainer(containerId);
  // Canonical Dockerode shape: argv is passed directly to execve, no shell
  // parsing.  Constant array — must not fire, locked in by EXCLUDES.
  await container.exec({ Cmd: ["ls", "-la"], AttachStdout: true });
}

export async function dockerodeOpaqueArrayVar(
  containerId: string,
  argv: string[]
): Promise<void> {
  const container = docker.getContainer(containerId);
  // Variable, not literal — detector inspects only literal arrays.
  await container.exec({ Cmd: argv, AttachStdout: true });
}

export async function execSyncWithEnv(_req: any): Promise<void> {
  const { execSync } = require("child_process");
  // Existing carve-out: the env arg is never a shell-injection payload, the
  // bare destructured-import `execSync` gate (=execSync) restricts
  // payload_args to arg 0 (the command string).  Locked in.
  execSync("npx playwright test", { env: process.env });
}
