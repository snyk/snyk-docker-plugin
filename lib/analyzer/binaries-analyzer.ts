import { Binary } from './types';

export {
  analyze,
};

async function analyze(
  targetImage: string,
  installedPackages: string[],
  options?: any,
  pkgManager?: string) {
  const binaries = await getBinaries(
    targetImage, installedPackages, options, pkgManager);
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

async function getBinaries(
  targetImage: string,
  installedPackages: string[],
  options?: any,
  pkgManager?: string,
  ): Promise<Binary[]> {
  const binaries: Binary[] = [];
  for (const versionExtractor of Object.keys(binaryVersionExtractors)) {
    const extractor = binaryVersionExtractors[versionExtractor];
    if (extractor.installedByPackageManager(
      installedPackages, options, pkgManager)) {
      continue;
    }
    const binary = await extractor.extract(targetImage);
    if (binary) {
      binaries.push(binary);
    }
  }
  return binaries;
}
