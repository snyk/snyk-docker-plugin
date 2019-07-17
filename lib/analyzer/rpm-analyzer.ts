import { Docker } from "../docker";
import { AnalyzerPkg } from "./types";

export { analyze };

async function analyze(docker: Docker) {
  const pkgs = await getPackages(docker);
  return {
    Image: docker.getTargetImage(),
    AnalyzeType: "Rpm",
    Analysis: pkgs,
  };
}

function getPackages(docker: Docker) {
  return docker
    .run("rpm", [
      "--nodigest",
      "--nosignature",
      "-qa",
      "--qf",
      '"%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SIZE}\n"',
    ])
    .catch((error) => {
      const stderr = error.stderr;
      if (typeof stderr === "string" && stderr.indexOf("not found") >= 0) {
        return { stdout: "", stderr: "" };
      }
      throw error;
    })
    .then((output) => parseOutput(output.stdout));
}

function parseOutput(output: string) {
  const pkgs: AnalyzerPkg[] = [];
  for (const line of output.split("\n")) {
    parseLine(line, pkgs);
  }
  return pkgs;
}

function parseLine(text: string, pkgs: AnalyzerPkg[]) {
  const [name, version, size] = text.split("\t");
  if (name && version && size) {
    const pkg: AnalyzerPkg = {
      Name: name,
      Version: version,
      Source: undefined,
      Provides: [],
      Deps: {},
      AutoInstalled: undefined,
    };
    pkgs.push(pkg);
  }
}
