import { Binary } from './types';

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

const binaryVersionExtractors = {
  node: require('./binary-version-extractors/node'),
  openjdk: require('./binary-version-extractors/openjdk-jre'),
};

async function getBinaries(targetImage: string, installedPackages: string[])
  : Promise<Binary[]> {
  const binaries: Binary[] = [];
  for (const versionExtractor of Object.keys(binaryVersionExtractors)) {
    const extractor = binaryVersionExtractors[versionExtractor];
    if (installedByPackageManager(extractor.packageNames, installedPackages)) {
      continue;
    }
    const binary = await extractor.extract(targetImage);
    if (binary) {
      binaries.push(binary);
    }
  }
  return binaries;
}

function installedByPackageManager(
  binaryPkgNames: string[],
  installedPackages: string[]): boolean {
  return installedPackages
    .filter(pkg => binaryPkgNames.indexOf(pkg) > -1).length > 0;
}
