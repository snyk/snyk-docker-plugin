import {
  DockerPull,
  DockerPullOptions,
  DockerPullResult,
} from "@snyk/snyk-docker-pull";
import * as Debug from "debug";
import * as Modem from "docker-modem";
import { createWriteStream } from "fs";
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

  public async pullCli(
    targetImage: string,
    options?: DockerOptions,
  ): Promise<subProcess.CmdOutput> {
    const opts: string[] = ["pull", targetImage];
    if (options?.platform) {
      opts.push(`--platform=${options.platform}`);
    }

    return subProcess.execute("docker", opts);
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
    // Depending on how `DOCKER_HOST` is set, we might connect to a socket or an
    // HTTP server. However, the default http.globalAgent might be setup to use
    // HTTP_PROXY, which we do not want to do when connecting to a socket. As
    // such, if the socketPath is set, we do not use the global agent.
    if (modem.socketPath !== "") {
      modem.agent = false; // causes a new Agent with default values to be used.
    }

    return new Promise<void>((resolve, reject) => {
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
    return subProcess.execute("docker", ["inspect", targetImage]);
  }
}
