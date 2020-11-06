import { display } from "./display";
import * as dockerFile from "./dockerfile";
import { scan } from "./scan";
import {
  ContainerTarget,
  Fact,
  Identity,
  ManifestFile,
  PluginResponse,
  ScanResult,
} from "./types";

export {
  scan,
  display,
  dockerFile,
  ScanResult,
  PluginResponse,
  ContainerTarget,
  Identity,
  Fact,
  ManifestFile,
};

setImmediate(async () => {
  try {
    const result = await scan({
      path: "traefik",
      // path:
      //   "docker-archive:/Users/agatakrajewska/Source/snyk-docker-plugin/test/fixtures/docker-archives/docker-save/java.tar",
      "app-vulns": true,
    });
    // tslint:disable-next-line: no-console
    console.log(result);
  } catch (error) {
    // tslint:disable-next-line: no-console
    console.log(error);
  }
});
