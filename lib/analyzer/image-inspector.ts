import * as subProcess from '../sub-process';

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

async function detect(targetImage: string): Promise<Inspect> {
  try {
    const info = await subProcess.execute('docker', ['inspect', targetImage]);
    return JSON.parse(info.stdout)[0];
  } catch (error) {
    throw new Error(`Docker image was not found locally: ${targetImage}`);
  }
}
