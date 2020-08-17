import {
  DockerPull,
  DockerPullOptions,
  DockerPullResult,
} from "@snyk/snyk-docker-pull";
import * as Debug from "debug";
import * as Modem from "docker-modem";
import { eventLoopSpinner } from "event-loop-spinner";
import { createWriteStream } from "fs";
import * as minimatch from "minimatch";
import { platform } from "os";
import * as fspath from "path";
import { Stream } from "stream";
import * as lsu from "./ls-utils";
import * as subProcess from "./sub-process";

export { Docker, DockerOptions };

interface DockerOptions {
  host?: string;
  tlsVerify?: string;
  tlsCert?: string;
  tlsCaCert?: string;
  tlsKey?: string;
  socketPath?: string;
}

const SystemDirectories = ["dev", "proc", "sys"];
const debug = Debug("snyk");

class Docker {
  public static async binaryExists(): Promise<boolean> {
    try {
      await subProcess.execute("docker", ["version"]);
      return true;
    } catch (e) {
      return false;
    }
  }

  public static run(args: string[], options?: DockerOptions) {
    return subProcess.execute("docker", [
      ...Docker.createOptionsList(options),
      ...args,
    ]);
  }

  private static createOptionsList(options: any) {
    const opts: string[] = [];
    if (!options) {
      return opts;
    }
    if (options.host) {
      opts.push(`--host=${options.host}`);
    }
    if (options.tlscert) {
      opts.push(`--tlscert=${options.tlscert}`);
    }
    if (options.tlscacert) {
      opts.push(`--tlscacert=${options.tlscacert}`);
    }
    if (options.tlskey) {
      opts.push(`--tlskey=${options.tlskey}`);
    }
    if (options.tlsverify) {
      opts.push(`--tlsverify=${options.tlsverify}`);
    }
    return opts;
  }

  private optionsList: string[];
  private socketPath: string;

  constructor(private targetImage: string, options?: DockerOptions) {
    this.optionsList = Docker.createOptionsList(options);
    this.socketPath =
      options?.socketPath ||
      (platform() === "win32"
        ? "\\\\.\\pipe\\docker_engine"
        : "/var/run/docker.sock");
  }

  /**
   * Runs the command, catching any expected errors and returning them as normal
   * stderr/stdout result.
   */
  public async runSafe(
    cmd: string,
    args: string[] = [],
    // no error is thrown if any of listed errors is found in stderr
    ignoreErrors: string[] = ["No such file", "not found"],
  ) {
    try {
      return await this.run(cmd, args);
    } catch (error) {
      const stderr: string = error.stderr;
      if (typeof stderr === "string") {
        if (ignoreErrors.some((errMsg) => stderr.indexOf(errMsg) >= 0)) {
          return { stdout: error.stdout, stderr };
        }
      }
      throw error;
    }
  }

  public run(cmd: string, args: string[] = []) {
    return subProcess.execute("docker", [
      ...this.optionsList,
      "run",
      "--rm",
      "--entrypoint",
      '""',
      "--network",
      "none",
      this.targetImage,
      cmd,
      ...args,
    ]);
  }

  public async pull(
    registry: string,
    repo: string,
    tag: string,
    imageSavePath: string,
    username?: string,
    password?: string,
  ): Promise<DockerPullResult> {
    const dockerPull = new DockerPull();
    const opt: DockerPullOptions = {
      username,
      password,
      loadImage: false,
      imageSavePath,
    };
    return await dockerPull.pull(registry, repo, tag, opt);
  }

  public async pullCli(targetImage: string) {
    return subProcess.execute("docker", ["pull", targetImage]);
  }

  public async save(targetImage: string, destination: string) {
    const request = {
      path: `/images/${targetImage}/get?`,
      method: "GET",
      isStream: true,
      statusCodes: {
        200: true,
        400: "bad request",
        404: "not found",
        500: "server error",
      },
    };

    debug(
      `Docker.save: targetImage: ${targetImage}, destination: ${destination}`,
    );

    const modem: Modem = new Modem({ socketPath: this.socketPath });

    return new Promise((resolve, reject) => {
      modem.dial(request, (err, stream: Stream) => {
        if (err) {
          return reject(err);
        }

        const writeStream = createWriteStream(destination);
        writeStream.on("error", (err) => {
          reject(err);
        });
        writeStream.on("finish", () => {
          resolve();
        });

        stream.on("error", (err) => {
          reject(err);
        });
        stream.on("end", () => {
          writeStream.end();
        });

        stream.pipe(writeStream);
      });
    });
  }

  public async inspectImage(targetImage: string) {
    return subProcess.execute("docker", [
      ...this.optionsList,
      "inspect",
      targetImage,
    ]);
  }

  public async catSafe(filename: string) {
    return this.runSafe("cat", [filename]);
  }

  public async lsSafe(path: string, recursive?: boolean) {
    let params = "-1ap";
    if (recursive) {
      params += "R";
    }

    const ignoreErrors = [
      "No such file",
      "file not found",
      "Permission denied",
    ];

    return this.runSafe("ls", [params, path], ignoreErrors);
  }

  /**
   * Find files on a docker image according to a given list of glob expressions.
   */
  public async findGlobs(
    globs: string[],
    exclusionGlobs: string[] = [],
    path: string = "/",
    recursive: boolean = true,
    excludeRootDirectories: string[] = SystemDirectories,
  ) {
    let root: lsu.DiscoveredDirectory;
    const res: string[] = [];

    if (recursive && path === "/") {
      // When scanning from the root of a docker image we need to
      // exclude system files e.g. /proc, /sys, etc. to make the
      // operation less expensive.

      const outputRoot = await this.lsSafe("/", false);
      root = lsu.parseLsOutput(outputRoot.stdout);

      for (const subdir of root.subDirs) {
        if (excludeRootDirectories.includes(subdir.name)) {
          continue;
        }

        const subdirOutput = await this.lsSafe("/" + subdir.name, true);
        const subdirRecursive = lsu.parseLsOutput(subdirOutput.stdout);

        await lsu.iterateFiles(subdirRecursive, (f) => {
          f.path = "/" + subdir.name + f.path;
        });

        subdir.subDirs = subdirRecursive.subDirs;
        subdir.files = subdirRecursive.files;
      }
    } else {
      const output = await this.lsSafe(path, recursive);

      if (eventLoopSpinner.isStarving()) {
        await eventLoopSpinner.spin();
      }

      root = lsu.parseLsOutput(output.stdout);
    }

    await lsu.iterateFiles(root, (f) => {
      const filepath = fspath.join(f.path, f.name);
      let exclude = false;
      for (const g of exclusionGlobs) {
        if (!exclude && minimatch(filepath, g)) {
          exclude = true;
        }
      }
      if (!exclude) {
        for (const g of globs) {
          if (minimatch(filepath, g)) {
            res.push(filepath);
          }
        }
      }
    });

    return res;
  }
}
