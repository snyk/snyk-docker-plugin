import subProcess from '../sub-process';

export {
  detect,
};

async function detect(targetImage) {
  const info = await subProcess.execute('docker', ['inspect', targetImage]);
  return JSON.parse(info)[0].Id;
}
