export interface PythonRequirement {
  name: string;
  version?: string;
  specifier?: string;
  extras?: string[];
  extraEnvMarkers?: string[];
}

export interface PythonPackage {
  name: string;
  version: string;
  dependencies: PythonRequirement[];
}

export interface PythonMetadataFiles {
  [name: string]: PythonPackage[];
}
