import { PluginResponse } from "./types";

export async function experimentalAnalysis(
  options: any,
): Promise<PluginResponse> {
  // assume Distroless scanning
  return distroless(options);
}

// experimental flow expected to be merged with the static analysis when ready
export async function distroless(options: any): Promise<PluginResponse> {
  // assumption #1: the image is present in the local Docker daemon
  // assumption #2: the `docker` binary is available locally
  throw new Error("not implemented");
}
