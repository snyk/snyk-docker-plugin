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

// tslint:disable:no-console
setImmediate(async () => {
  try {
    const result = await scan({
      // path:
      // ""
        // "docker-archive:/Users/shani/test-containers/buster-log4j/buster-log4j.tar",
			// Options for "path" include, but not limited to:
	
			// #1 [docker/oci]-arcive:/full/path/to/image.tar	
      // "docker-archive:/Users/shani/Downloads/dummy.tar",

			// #2 public image
			// "alpine",

			// #3 remote registry (but then you'd also need username and password)
			// "shanihub/my-image:latest",
      // username: 'shanihub',
      // password: 's3cr3t',

			// #4 local registry

		// other options, same as flags that you'd enter if you were running the CLI
		// "app-vulns": true,
      // "shaded-jars-depth": "2",
    //  "file": "/Users/shani/test-containers/buster-log4j/Dockerfile"
		// ...

    });

    const depGraph = result.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )?.data;
    console.log(depGraph);
  } catch (error) {
    console.log(error);
  }
});