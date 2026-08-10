export interface DotnetPackage {
  name: string;
  version: string;
}

export interface DotnetPackageWithDependencies extends DotnetPackage {
  dependencies: string[];
}

export interface DotnetGraphParseResult {
  rootName: string;
  rootVersion: string;
  directDependencies: string[];
  packages: DotnetPackageWithDependencies[];
}
