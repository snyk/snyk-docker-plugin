import { Docker } from "../docker";

export { detect };
interface Inspect {
  Id: string;
  RootFS: {
    Type: string;
    Layers: string[];
  };
}

async function detect(docker: Docker): Promise<Inspect> {
  try {
    const info = await docker.inspect();
    return JSON.parse(info.stdout)[0];
  } catch (error) {
    if (error.stderr.includes("No such object")) {
      throw new Error(
        `Docker error: image was not found locally: ${docker.getTargetImage()}`,
      );
    }
    throw new Error(`Docker error: ${error.stderr}`);
  }
}
