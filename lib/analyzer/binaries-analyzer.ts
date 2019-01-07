import { Docker } from '../docker';
import { Binary } from './types';

const semver = require('semver');

export {
  analyze,
};

async function analyze(targetImage: string, installedPackages: string[]) {
  const binaries = await getBinaries(targetImage, installedPackages);
  return {
    Image: targetImage,
    AnalyzeType: 'binaries',
    Analysis: binaries,
  };
}

async function getBinaries(targetImage: string, installedPackages: string[])
  : Promise<Binary[]> {
  const binaries: Binary[] = [];
  const node = await getNodeBinary(targetImage, installedPackages);
  if (node) {
     binaries.push(node);
  }
  return binaries;
}

function getNodeBinary(targetImage: string, installedPackages: string[])
  : Promise<Binary | null> | null {
  if (installedByPackageManager(['node', 'nodejs'], installedPackages)) {
    return null;
  }
  return new Docker(targetImage).run('node', [ '--version' ])
    .catch(stderr => {
      if (typeof stderr === 'string' && stderr.indexOf('not found') >= 0) {
        return '';
      }
      throw new Error(stderr);
    })
    .then(parseNodeBinary);
}

function installedByPackageManager(
  binaryPkgNames: string[],
  installedPackages: string[]): boolean {
  return installedPackages
    .filter(pkg => binaryPkgNames.indexOf(pkg) > -1).length > 0;
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
