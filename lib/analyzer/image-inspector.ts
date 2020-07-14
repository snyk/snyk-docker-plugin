import * as Debug from "debug";
import * as fs from "fs";
import * as mkdirp from "mkdirp";
import * as path from "path";

import { Docker, DockerOptions } from "../docker";
import {
  ArchiveResult,
  DestinationDir,
  DockerInspectOutput,
  ImageDetails,
} from "./types";

export { detect, getImageArchive, extractImageDetails, pullIfNotLocal };

const debug = Debug("snyk");

async function detect(
  targetImage: string,
  options?: DockerOptions,
): Promise<DockerInspectOutput> {
  const docker = new Docker(targetImage, options);
  const info = await docker.inspectImage(targetImage);
  return JSON.parse(info.stdout)[0];
}

function cleanupCallback(imagePath: string, imageName: string) {
  return () => {
    const fullImagePath = path.join(imagePath, imageName);
    if (fs.existsSync(fullImagePath)) {
      fs.unlinkSync(fullImagePath);
    }
    fs.rmdirSync(imagePath);
  };
}

/**
 * In the case that an `ImageType.Identifier` is detected we need to produce
 * an image archive, either by saving the image if it's already loaded into
 * the local docker daemon, or by pulling the image from a remote registry and
 * saving it to the filesystem directly.
 *
 * Users may also provide us with a URL to an image in a Docker compatible
 * remote registry.
 *
 * @param {string} targetImage - The image to test, this could be in one of
 *    the following forms:
 *      * [registry/]<repo>/<image>[:tag]
 *      * <repo>/<image>[:tag]
 *      * <image>[:tag]
 *    In the case that a registry is not provided, the plugin will default
 *    this to Docker Hub. If a tag is not provided this will default to
 *    `latest`.
 * @param {string} [username] - Optional username for private repo auth.
 * @param {string} [password] - Optional password for private repo auth.
 */
async function getImageArchive(
  targetImage: string,
  imageSavePath: string,
  username?: string,
  password?: string,
): Promise<ArchiveResult> {
  const docker = new Docker(targetImage);
  mkdirp.sync(imageSavePath);
  const destination: DestinationDir = {
    name: imageSavePath,
    removeCallback: cleanupCallback(imageSavePath, "image.tar"),
  };
  const saveLocation: string = path.join(destination.name, "image.tar");

  try {
    await docker.save(targetImage, saveLocation);

    return {
      path: saveLocation,
      removeArchive: destination.removeCallback,
    };
  } catch {
    debug(
      `${targetImage} does not exist locally, proceeding to pull image from remote registry.`,
    );
  }

  if (await Docker.binaryExists()) {
    try {
      if (username || password) {
        debug(
          "using local docker binary credentials. the credentials you provided will be ignored",
        );
      }

      await docker.pullCli(targetImage);
      await docker.save(targetImage, saveLocation);
      return {
        path: saveLocation,
        removeArchive: destination.removeCallback,
      };
    } catch (err) {
      debug(`couldn't pull ${targetImage} using docker binary: ${err}`);
    }
  }

  const { hostname, imageName, tag } = await extractImageDetails(targetImage);
  debug(
    `Attempting to pull: registry: ${hostname}, image: ${imageName}, tag: ${tag}`,
  );
  await docker.pull(
    hostname,
    imageName,
    tag,
    imageSavePath,
    username,
    password,
  );
  return {
    path: saveLocation,
    removeArchive: destination.removeCallback,
  };
}

async function extractImageDetails(targetImage: string): Promise<ImageDetails> {
  let remainder: string;
  let hostname: string;
  let imageName: string;
  let tag: string;

  // We need to detect if the `targetImage` is part of a URL. Based on the Docker specification,
  // the hostname should contain a `.` or `:` before the first instance of a `/` otherwise the
  // default hostname will be used (registry-1.docker.io). ref: https://stackoverflow.com/a/37867949
  const i = targetImage.indexOf("/");
  if (
    i === -1 ||
    (!targetImage.substring(0, i).includes(".") &&
      !targetImage.substring(0, i).includes(":") &&
      targetImage.substring(0, i) !== "localhost")
  ) {
    hostname = "registry-1.docker.io";
    remainder = targetImage;
    [imageName, tag] = remainder.split(":");
    imageName =
      imageName.indexOf("/") === -1 ? "library/" + imageName : imageName;
  } else {
    hostname = targetImage.substring(0, i);
    remainder = targetImage.substring(i + 1);
    [imageName, tag] = remainder.split(":");
  }

  // Assume the latest tag if no tag was found.
  tag = tag || "latest";

  return {
    hostname,
    imageName,
    tag,
  };
}

async function pullIfNotLocal(targetImage: string, options?: DockerOptions) {
  const docker = new Docker(targetImage);
  try {
    await docker.inspectImage(targetImage);
    return;
  } catch (err) {
    // image doesn't exist locally
  }
  await docker.pullCli(targetImage);
}
