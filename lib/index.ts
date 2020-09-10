import * as dockerFile from "./docker-file";
import { experimentalAnalysis } from "./experimental";
import * as staticUtil from "./static";
import {
  AppDepsScanResult,
  OsDepsScanResult,
  ScanOptions,
  ScanResult,
} from "./types";

export { scan, dockerFile, OsDepsScanResult, AppDepsScanResult, ScanResult };

async function scan(
  root: string,
  targetFile?: string,
  options?: Partial<ScanOptions>,
): Promise<ScanResult[]> {
  const targetImage = root;

  const dockerfileAnalysis = await dockerFile.readDockerfileAndAnalyse(
    targetFile,
  );

  if (options && options.experimental) {
    return await experimentalAnalysis(targetImage, dockerfileAnalysis, options);
  }

  return await staticUtil.analyzeStatically(
    targetImage,
    dockerfileAnalysis,
    options,
  );
}

setImmediate(async () => {
  const result = await scan("snyk/kubernetes-monitor:1.32.2", "Dockerfile", {
    experimental: true,
    appScan: true,
    "app-vulns": true,
  });
  // tslint:disable-next-line: no-console
  console.log(JSON.stringify(result));
});
