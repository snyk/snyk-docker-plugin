export interface CargoPackageDependency {
  name: string;
  version?: string;
}

export interface CargoPackage {
  name: string;
  version: string;
  dependencies: CargoPackageDependency[];
}
