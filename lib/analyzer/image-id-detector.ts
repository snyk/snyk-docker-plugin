import * as subProcess from '../sub-process';

export {
  detect,
};

async function detect(targetImage: string): Promise<string> {
  try {
    const info = await subProcess.execute('docker', ['inspect', targetImage]);
    return JSON.parse(info)[0].Id;
  } catch (error) {
    throw new Error(`Docker image was not found locally: ${targetImage}`);
  }
}
