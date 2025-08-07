import * as childProcess from "child_process";
import * as os from "node:os";
import { escapeAll, quoteAll } from "shescape/stateless";

export { execute, CmdOutput };
interface CmdOutput {
  stdout: string;
  stderr: string;
}

function execute(
  command: string,
  args: string[],
  options?,
): Promise<CmdOutput> {
  const spawnOptions: any = {
    shell: false,
    env: { ...process.env },
  };
  if (options && options.cwd) {
    spawnOptions.cwd = options.cwd;
  }

  if (args) {
    // Best practices, also security-wise, is to not invoke processes in a shell, but as a stand-alone command.
    // However, on Windows, we need to invoke the command in a shell, due to internal NodeJS problems with this approach
    // see: https://nodejs.org/docs/latest-v24.x/api/child_process.html#spawning-bat-and-cmd-files-on-windows
    const isWinLocal = /^win/.test(os.platform());
    if (isWinLocal) {
      spawnOptions.shell = true;
      // Further, we distinguish between quoting and escaping arguments since quoteAll does not support quoting without
      // supplying a shell, but escapeAll does.
      // See this (very long) discussion for more details: https://github.com/ericcornelissen/shescape/issues/2009
      args = quoteAll(args, { ...spawnOptions, flagProtection: false });
    } else {
      args = escapeAll(args, { ...spawnOptions, flagProtection: false });
    }
  }

  // Before spawning an external process, we look if we need to restore the system proxy configuration,
  // which overrides the cli internal proxy configuration.
  if (process.env.SNYK_SYSTEM_HTTP_PROXY !== undefined) {
    spawnOptions.env.HTTP_PROXY = process.env.SNYK_SYSTEM_HTTP_PROXY;
  }
  if (process.env.SNYK_SYSTEM_HTTPS_PROXY !== undefined) {
    spawnOptions.env.HTTPS_PROXY = process.env.SNYK_SYSTEM_HTTPS_PROXY;
  }
  if (process.env.SNYK_SYSTEM_NO_PROXY !== undefined) {
    spawnOptions.env.NO_PROXY = process.env.SNYK_SYSTEM_NO_PROXY;
  }

  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";

    const proc = childProcess.spawn(command, args, spawnOptions);

    // Handle spawn errors (e.g., ENOENT when command doesn't exist)
    proc.on("error", (error) => {
      stderr = error.message;
      reject({ stdout, stderr });
    });

    proc.stdout.on("data", (data) => {
      stdout = stdout + data;
    });
    proc.stderr.on("data", (data) => {
      stderr = stderr + data;
    });

    proc.on("close", (code) => {
      const output = { stdout, stderr };
      if (code !== 0) {
        return reject(output);
      }
      resolve(output);
    });
  }) as Promise<CmdOutput>;
}
