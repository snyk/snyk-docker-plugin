import * as dockerFile from "./docker-file";
import { experimentalAnalysis } from "./experimental";
import {
  ContainerTarget,
  Fact,
  Identity,
  PluginOptions,
  PluginResponse,
  ScanResult,
} from "./types";

export {
  scan,
  dockerFile,
  ScanResult,
  PluginResponse,
  ContainerTarget,
  Identity,
  Fact,
};

async function scan(options?: Partial<PluginOptions>): Promise<PluginResponse> {
  if (!options) {
    throw new Error("No plugin options provided");
  }

  const targetImage = options.path;
  if (!targetImage) {
    throw new Error("No image identifier or path provided");
  }

  const dockerfilePath = options.file;
  const dockerfileAnalysis = await dockerFile.readDockerfileAndAnalyse(
    dockerfilePath,
  );

  return await experimentalAnalysis(targetImage, dockerfileAnalysis, options);
}
