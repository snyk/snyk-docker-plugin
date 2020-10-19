export interface DockerFileAnalysis {
  baseImage?: string;
  dockerfilePackages: DockerFilePackages;
  dockerfileLayers: DockerFileLayers;
}

export interface DockerFilePackages {
  [packageName: string]: {
    instruction: string;
  };
}

export interface DockerFileLayers {
  [id: string]: {
    instruction: string;
  };
}
