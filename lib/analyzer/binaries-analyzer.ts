import { Docker } from '../docker';
import { Binary } from './types';

const semver = require('semver');

export {
  analyze,
};

async function analyze(targetImage: string) {
  const binaries = await getBinaries(targetImage);
  return {
    Image: targetImage,
    AnalyzeType: 'binaries',
    Analysis: binaries,
  };
}

async function getBinaries(targetImage: string): Promise<Binary[]> {
  const binaries: Binary[] = [];
  const node = await getNodeBinary(targetImage);
  if (node) {
     binaries.push(node);
  }
  return binaries;
}

function getNodeBinary(targetImage: string): Promise<Binary | null> {
  return new Docker(targetImage).run('node', [ '--version' ])
    .catch(stderr => {
      if (typeof stderr === 'string' && stderr.indexOf('not found') >= 0) {
        return '';
      }
      throw new Error(stderr);
    })
    .then(parseNodeBinary);
}

function parseNodeBinary(version: string) {
  const nodeVersion = semver.valid(version.trim());
  if (!nodeVersion) {
    return null;
  }

  return {
    name: 'node',
    version: nodeVersion,
  };
}
