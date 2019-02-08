import { Docker } from '../docker';

export {
  detect,
};
interface Inspect {
  Id: string;
  RootFS: {
    Type: string;
    Layers: string[]
  };
}

async function detect(targetImage: string, options?: any):
  Promise<Inspect> {
  try {
    const info = await new Docker(
      targetImage,
      options,
    )
    .inspect(targetImage);
    return JSON.parse(info.stdout)[0];
  } catch (error) {
    throw new Error(`Docker error: ${error.stderr}`);
  }
}
