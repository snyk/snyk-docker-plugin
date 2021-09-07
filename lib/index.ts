import { Binary } from "./analyzer/types";
import { display } from "./display";
import * as dockerFile from "./dockerfile";
import {
  analyseDockerfile,
  DockerFileAnalysis,
  updateDockerfileBaseImageName,
} from "./dockerfile";
import {
  DockerFileAnalysisErrorCode,
  UpdateDockerfileBaseImageNameErrorCode,
} from "./dockerfile/types";
import * as facts from "./facts";
import { scan } from "./scan";
import {
  AutoDetectedUserInstructions,
  ContainerTarget,
  Fact,
  FactType,
  Identity,
  ManifestFile,
  PluginResponse,
  ScanResult,
} from "./types";

export {
  scan,
  display,
  dockerFile,
  facts,
  ScanResult,
  PluginResponse,
  ContainerTarget,
  Identity,
  Fact,
  FactType,
  ManifestFile,
  analyseDockerfile,
  AutoDetectedUserInstructions,
  DockerFileAnalysis,
  DockerFileAnalysisErrorCode,
  updateDockerfileBaseImageName,
  UpdateDockerfileBaseImageNameErrorCode,
  Binary,
};

setImmediate(async () => {
  try {
    const result = await scan({
      path:
        "docker-archive:/Users/agatakrajewska/Source/archives/ast-dummy.tar",
      "app-vulns": true,
    });
    // tslint:disable-next-line: no-console
    const depGraph = result.scanResults[0].facts.find(
      (fact) => fact.type == "depGraph",
    )?.data;
    console.log(depGraph);
  } catch (error) {
    // tslint:disable-next-line: no-console
    console.log(error);
  }
});
