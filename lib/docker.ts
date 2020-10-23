import {
  DockerPull,
  DockerPullOptions,
  DockerPullResult,
} from "@snyk/snyk-docker-pull";
import * as Debug from "debug";
import * as Modem from "docker-modem";
import { createWriteStream } from "fs";
import { platform } from "os";
import { Stream } from "stream";
import * as subProcess from "./sub-process";

export { Docker, DockerOptions };

interface DockerOptions {
  host?: string;
  tlsVerify?: string;
  tlsCert?: string;
  tlsCaCert?: string;
  tlsKey?: string;
  socketPath?: string;
  platform?: string;
}

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

  constructor(options?: DockerOptions) {
    this.optionsList = Docker.createOptionsList(options);
    this.socketPath =
      options?.socketPath ||
      (platform() === "win32"
        ? "\\\\.\\pipe\\docker_engine"
        : "/var/run/docker.sock");
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

  public async isDockerExperimentalEnabled(): Promise<boolean> {
    const output = await subProcess.execute("docker", ["system", "info"]);
    return output.stdout.includes("Experimental: true");
  }

  public async pullCli(targetImage: string, options?: DockerOptions) {
    let platformOption: string = "";
    if (options?.platform) {
      if (await this.isDockerExperimentalEnabled()) {
        platformOption = `--platform=${options.platform}`;
      } else {
        throw new Error(
          '"--platform" is only supported on a Docker daemon with experimental features enabled',
        );
      }
    }

    return subProcess.execute("docker", ["pull", platformOption, targetImage]);
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

    const modem = new Modem();

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
}
