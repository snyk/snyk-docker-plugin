import { contentTypes } from "@snyk/docker-registry-v2-client";
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
    platform?: string,
  ): Promise<DockerPullResult> {
    const dockerPull = new DockerPull();
    const platformTokens = platform ? platform.split("/") : undefined;
    let os: string = "linux";
    let architecture: string = "amd64";
    let variant: string | undefined;

    if (platformTokens) {
      const platformTokensLen = platformTokens.length;
      if (platformTokensLen <= 1) {
        throw Error(
          "Invalid platform string. Please provide a platform name that follows os/arch[/variant] format.",
        );
      }
      os = platformTokens[0];
      architecture = platformTokens[1];
      variant = platformTokens[2];
    }
    const opt: DockerPullOptions = {
      username,
      password,
      loadImage: false,
      platform: platformTokens ? { os, architecture, variant } : undefined,
      imageSavePath,
      reqOptions: {
        acceptManifest: [
          contentTypes.OCI_MANIFEST_V1,
          contentTypes.OCI_INDEX_V1,
          contentTypes.MANIFEST_V2,
          contentTypes.MANIFEST_LIST_V2,
        ].join(","),
      },
    };
    return await dockerPull.pull(registry, repo, tag, opt);
  }

  public async pullCli(
    targetImage: string,
    options?: DockerOptions,
  ): Promise<subProcess.CmdOutput> {
    const args: string[] = ["pull", targetImage];
    if (options?.platform) {
      args.push(`--platform=${options.platform}`);
    }

    return subProcess.execute("docker", args);
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
