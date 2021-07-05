// Question: This is used by autoDetectedUserInstructions fact type, traits doesn't make sense to be shared here.
export interface DockerFileAnalysis {
  baseImage?: string;
  dockerfilePackages: DockerFilePackages;
  dockerfileLayers: DockerFileLayers;
  error?: DockerFileAnalysisError;
}

export interface DockerFileAnalysisError {
  code: DockerFileAnalysisErrorCode;
}

export enum DockerFileAnalysisErrorCode {
  /**
   * Dockerfile must begin with a FROM instruction. This may be after parser directives, comments, and globally scoped ARGs.
   */
  BASE_IMAGE_NAME_NOT_FOUND = "BASE_IMAGE_NAME_NOT_FOUND",
  /**
   * Dockerfile base image is non resolvable because ARG instructions do not have default values.
   */
  BASE_IMAGE_NON_RESOLVABLE = "BASE_IMAGE_NON_RESOLVABLE",
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

export interface UpdateDockerfileBaseImageNameResult {
  contents: string;
  error?: UpdateDockerfileBaseImageNameError;
}

export interface UpdateDockerfileBaseImageNameError {
  code: UpdateDockerfileBaseImageNameErrorCode;
}

export enum UpdateDockerfileBaseImageNameErrorCode {
  BASE_IMAGE_NAME_FRAGMENTED = "BASE_IMAGE_NAME_FRAGMENTED",
  BASE_IMAGE_NAME_NOT_FOUND = "BASE_IMAGE_NAME_NOT_FOUND",
  DOCKERFILE_GENERATION_FAILED = "DOCKERFILE_GENERATION_FAILED",
}
