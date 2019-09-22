import { Docker, DockerOptions } from "../../../docker";

export { getApkDbFileContent };

function getApkDbFileContent(targetImage: string, options?: DockerOptions) {
  return getPackages(targetImage, options);
}

function getPackages(targetImage: string, options?: DockerOptions) {
  return new Docker(targetImage, options)
    .catSafe("/lib/apk/db/installed")
    .then((output) => output.stdout);
}
