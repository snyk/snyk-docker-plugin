import * as childProcess from "child_process";

export {
  execute,
  executeAsStream,
  CmdOutput,
  StreamData,
  ExecuteAsStreamCallback,
};
interface CmdOutput {
  stdout: string;
  stderr: string;
}

interface StreamData {
  data?: Buffer | string;
  err?: Buffer | string;
  exitCode?: number;
}

type ExecuteAsStreamCallback = (sd: StreamData) => any;

function execute(
  command: string,
  args?: string[],
  options?,
): Promise<CmdOutput> {
  const spawnOptions: any = { shell: true };
  if (options && options.cwd) {
    spawnOptions.cwd = options.cwd;
  }

  return new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";

    const proc = childProcess.spawn(command, args, spawnOptions);
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

function executeAsStream(
  command: string,
  cb: ExecuteAsStreamCallback,
  args?: string[],
): Promise<void> {
  return new Promise((resolve, reject) => {
    const spawnOptions: any = { shell: true };

    const proc = childProcess.spawn(command, args, spawnOptions);
    proc.stdout.on("data", (data) => {
      cb({ data });
    });

    proc.stderr.on("data", (data) => {
      cb({ err: data });
    });

    proc.on("close", (exitCode) => {
      cb({ exitCode });

      resolve();
    });
  });
}
