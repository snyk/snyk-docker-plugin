export interface ComposerPackage {
  name: string;
  version: string;
}

export interface ParseComposerLockOptions {
  shouldIncludeDevDependencies?: boolean;
}
