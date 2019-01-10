import { Docker } from '../../docker';
import { Binary } from '../types';

const semver = require('semver');

export {
  extract,
  packageNames,
};

const packageNames = ['node', 'nodejs'];

async function extract(targetImage: string): Promise<Binary | null> {
  try {
    const binaryVersion = await new Docker(targetImage).
      run('node', [ '--version' ]);
    return parseNodeBinary(binaryVersion);
  } catch (stderr) {
    if (typeof stderr === 'string' && stderr.indexOf('not found') >= 0) {
      return null;
    }
    throw new Error(stderr);
  }
}

function parseNodeBinary(version: string) {
  const nodeVersion = semver.valid(version && version.trim());
  if (!nodeVersion) {
    return null;
  }
  return {
    name: 'node',
    version: nodeVersion,
  };
}
