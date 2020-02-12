import { Docker, DockerOptions } from "../docker";
import { DockerInspectOutput } from "./types";

export { detect, pullIfNotLocal };

async function detect(
  targetImage: string,
  options?: DockerOptions,
): Promise<DockerInspectOutput> {
  const docker = new Docker(targetImage, options);
  const info = await docker.inspectImage(targetImage);
  return JSON.parse(info.stdout)[0];
}

async function pullIfNotLocal(targetImage: string, options?: DockerOptions) {
  const docker = new Docker(targetImage);
  try {
    await docker.inspectImage(targetImage);
    return;
  } catch (err) {
    // image doesn't exist locally
  }
  await docker.pull(targetImage);
}
