import * as path from "path";

import { readDockerfileAndAnalyse } from "../dockerfile";
import * as facts from "../facts";
import { PluginResponse } from "../types";
import { PLUGIN_VERSION } from "../version";
import { buildCycloneDxBom, SbomSource } from "./cyclonedx";

/**
 * Handles `--sbom` when only a Dockerfile was supplied (no image identifier
 * or archive path). Produces a `PluginResponse` with a single scan result
 * carrying the sbom fact plus dockerfile analysis, and no `depGraph` fact
 * since there is no image to build a dependency tree from.
 */
export async function scanDockerfileOnly(
  file: string,
): Promise<PluginResponse> {
  const dockerfileAnalysis = await readDockerfileAndAnalyse(file);

  const sbomSource: SbomSource = {
    dockerfileAnalysis,
  };
  const sbomFact: facts.SbomFact = {
    type: "sbom",
    data: buildCycloneDxBom(sbomSource),
  };
  const dockerfileAnalysisFact: facts.DockerfileAnalysisFact = {
    type: "dockerfileAnalysis",
    data: dockerfileAnalysis!,
  };
  const pluginVersionFact: facts.PluginVersionFact = {
    type: "pluginVersion",
    data: PLUGIN_VERSION,
  };

  const targetImage = dockerfileAnalysis?.baseImage ?? path.basename(file);

  return {
    scanResults: [
      {
        target: { image: targetImage },
        identity: { type: "dockerfile", targetFile: file },
        facts: [sbomFact, dockerfileAnalysisFact, pluginVersionFact],
      },
    ],
  };
}
