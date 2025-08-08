import * as Debug from "debug";
import * as fs from "fs";
import * as mkdirp from "mkdirp";
import * as path from "path";

import { Docker, DockerOptions } from "../docker";
import { ImageName } from "../extractor/image";

import type { DockerPullResult } from "@snyk/snyk-docker-pull";
import type {
  ArchiveResult,
  DestinationDir,
  DockerInspectOutput,
  ImageDetails,
} from "./types";

export { getImageArchive, extractImageDetails, pullIfNotLocal };

const debug = Debug("snyk");

async function getInspectResult(
  docker: Docker,
  targetImage: string,
): Promise<DockerInspectOutput> {
  const info = await docker.inspectImage(targetImage);
  return JSON.parse(info.stdout)[0];
}

function cleanupCallback(imageFolderPath: string, imageName: string) {
  return () => {
    const fullImagePath = path.join(imageFolderPath, imageName);
    if (fs.existsSync(fullImagePath)) {
      fs.unlinkSync(fullImagePath);
    }
    try {
      fs.rmdirSync(imageFolderPath);
    } catch (err) {
      debug(`Can't remove folder ${imageFolderPath}, got error ${err.message}`);
    }
  };
}

async function pullWithDockerBinary(
  docker: Docker,
  targetImage: string,
  saveLocation: string,
  username: string | undefined,
  password: string | undefined,
  platform: string | undefined,
): Promise<boolean> {
  try {
    if (username || password) {
      debug(
        "using local docker binary credentials. the credentials you provided will be ignored",
      );
    }
    await docker.pullCli(targetImage, { platform });
    await docker.save(targetImage, saveLocation);
    return true;
  } catch (err) {
    debug(`couldn't pull ${targetImage} using docker binary: ${err.message}`);

    handleDockerPullError(err.stderr, platform);

    return false;
  }
}

function handleDockerPullError(err: string, platform?: string) {
  if (err && err.includes("unknown operating system or architecture")) {
    throw new Error("Unknown operating system or architecture");
  }

  if (err.includes("operating system is not supported")) {
    throw new Error(`Operating system is not supported`);
  }

  const unknownManifestConditions = [
    "no matching manifest for",
    "manifest unknown",
  ];
  if (unknownManifestConditions.some((value) => err.includes(value))) {
    if (platform) {
      throw new Error(`The image does not exist for ${platform}`);
    }
    throw new Error(`The image does not exist for the current platform`);
  }

  if (err.includes("invalid reference format")) {
    throw new Error(`invalid image format`);
  }

  if (err.includes("unknown flag: --platform")) {
    throw new Error(
      '"--platform" is only supported on a Docker daemon with version later than 17.09',
    );
  }

  if (
    err ===
    '"--platform" is only supported on a Docker daemon with experimental features enabled'
  ) {
    throw new Error(err);
  }
}

async function pullFromContainerRegistry(
  docker: Docker,
  targetImage: string,
  imageSavePath: string,
  username: string | undefined,
  password: string | undefined,
  platform: string | undefined,
): Promise<DockerPullResult> {
  const { hostname, imageName, tag } = extractImageDetails(targetImage);
  debug(
    `Attempting to pull: registry: ${hostname}, image: ${imageName}, tag: ${tag}`,
  );
  try {
    return await docker.pull(
      hostname,
      imageName,
      tag,
      imageSavePath,
      username,
      password,
      platform,
    );
  } catch (err) {
    handleDockerPullError(err.message);
    throw err;
  }
}

async function pullImage(
  docker: Docker,
  targetImage: string,
  saveLocation: string,
  imageSavePath: string,
  username: string | undefined,
  password: string | undefined,
  platform: string | undefined,
): Promise<ImageName> {
  if (await Docker.binaryExists()) {
    const pullAndSaveSuccessful = await pullWithDockerBinary(
      docker,
      targetImage,
      saveLocation,
      username,
      password,
      platform,
    );
    if (pullAndSaveSuccessful) {
      return new ImageName(targetImage);
    }
  }

  const { indexDigest, manifestDigest } = await pullFromContainerRegistry(
    docker,
    targetImage,
    imageSavePath,
    username,
    password,
    platform,
  );

  const imageName = new ImageName(targetImage, {
    manifest: manifestDigest,
    index: indexDigest,
  });

  return imageName;
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
 * @param {string} [platform] - Optional platform parameter to pull specific image arch.
 */
async function getImageArchive(
  targetImage: string,
  imageSavePath: string,
  username?: string,
  password?: string,
  platform?: string,
): Promise<ArchiveResult> {
  const docker = new Docker();
  mkdirp.sync(imageSavePath);
  const destination: DestinationDir = {
    name: imageSavePath,
    removeCallback: cleanupCallback(imageSavePath, "image.tar"),
  };
  const saveLocation: string = path.join(destination.name, "image.tar");
  let inspectResult: DockerInspectOutput | undefined;

  try {
    inspectResult = await getInspectResult(docker, targetImage);
  } catch (error) {
    debug(
      `${targetImage} does not exist locally, proceeding to pull image.`,
      error.stack || error,
    );
  }

  if (inspectResult === undefined) {
    const imageName = await pullImage(
      docker,
      targetImage,
      saveLocation,
      imageSavePath,
      username,
      password,
      platform,
    );

    return {
      imageName,
      path: saveLocation,
      removeArchive: destination.removeCallback,
    };
  }

  if (
    platform !== undefined &&
    inspectResult &&
    !isLocalImageSameArchitecture(platform, inspectResult.Architecture)
  ) {
    const imageName = await pullImage(
      docker,
      targetImage,
      saveLocation,
      imageSavePath,
      username,
      password,
      platform,
    );
    return {
      imageName,
      path: saveLocation,
      removeArchive: destination.removeCallback,
    };
  } else {
    await docker.save(targetImage, saveLocation);
    const imageName = new ImageName(targetImage);
    return {
      imageName,
      path: saveLocation,
      removeArchive: destination.removeCallback,
    };
  }
}

function isImagePartOfURL(targetImage): boolean {
  // Based on the Docker spec, if the image contains a hostname, then the hostname should contain
  // a `.` or `:` before the first instance of a `/`. ref: https://stackoverflow.com/a/37867949
  if (!targetImage.includes("/")) {
    return false;
  }

  const partBeforeFirstForwardSlash = targetImage.split("/")[0];

  return (
    partBeforeFirstForwardSlash.includes(".") ||
    partBeforeFirstForwardSlash.includes(":") ||
    partBeforeFirstForwardSlash === "localhost"
  );
}

function extractHostnameFromTargetImage(targetImage: string): {
  hostname: string;
  remainder: string;
} {
  // We need to detect if the `targetImage` is part of a URL. If not, the default hostname will be
  // used (registry-1.docker.io). ref: https://stackoverflow.com/a/37867949
  const defaultHostname = "registry-1.docker.io";

  if (!isImagePartOfURL(targetImage)) {
    return { hostname: defaultHostname, remainder: targetImage };
  }

  const dockerFriendlyRegistryHostname = "docker.io/";
  if (targetImage.startsWith(dockerFriendlyRegistryHostname)) {
    return {
      hostname: defaultHostname,
      remainder: targetImage.substring(dockerFriendlyRegistryHostname.length),
    };
  }

  const i = targetImage.indexOf("/");
  return {
    hostname: targetImage.substring(0, i),
    remainder: targetImage.substring(i + 1),
  };
}

function extractImageNameAndTag(
  remainder: string,
  targetImage: string,
): { imageName: string; tag: string } {
  const defaultTag = "latest";

  if (!remainder.includes("@")) {
    const [imageName, tag] = remainder.split(":");

    return {
      imageName: appendDefaultRepoPrefixIfRequired(imageName, targetImage),
      tag: tag || defaultTag,
    };
  }

  const [imageName, tag] = remainder.split("@");

  return {
    imageName: appendDefaultRepoPrefixIfRequired(
      dropTagIfSHAIsPresent(imageName),
      targetImage,
    ),
    tag: tag || defaultTag,
  };
}

function appendDefaultRepoPrefixIfRequired(
  imageName: string,
  targetImage: string,
): string {
  const defaultRepoPrefix = "library/";

  if (isImagePartOfURL(targetImage) || imageName.includes("/")) {
    return imageName;
  }

  return defaultRepoPrefix + imageName;
}

function dropTagIfSHAIsPresent(imageName: string): string {
  if (!imageName.includes(":")) {
    return imageName;
  }

  return imageName.split(":")[0];
}

function extractImageDetails(targetImage: string): ImageDetails {
  const { hostname, remainder } = extractHostnameFromTargetImage(targetImage);
  const { imageName, tag } = extractImageNameAndTag(remainder, targetImage);
  return { hostname, imageName, tag };
}

function isLocalImageSameArchitecture(
  platformOption: string,
  inspectResultArchitecture: string,
): boolean {
  let platformArchitecture: string;
  try {
    // Note: this is using the same flag/input pattern as the new Docker buildx: eg. linux/arm64/v8
    platformArchitecture = platformOption.split("/")[1];
  } catch (error) {
    debug(`Error parsing platform flag: '${error.message}'`);
    return false;
  }

  return platformArchitecture === inspectResultArchitecture;
}

async function pullIfNotLocal(targetImage: string, options?: DockerOptions) {
  const docker = new Docker();
  try {
    await docker.inspectImage(targetImage);
    return;
  } catch (err) {
    // image doesn't exist locally
  }
  await docker.pullCli(targetImage);
}
