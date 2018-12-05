import * as fs from 'fs';
import { DockerfileParser, Instruction } from 'dockerfile-ast';
import {
  getPackagesFromRunInstructions,
  DockerFilePackages,
} from './instruction-parser';

export { analyseDockerfile };

interface DockerFileAnalysis {
  baseImage?: string;
  dockerfilePackages: DockerFilePackages;
}

async function analyseDockerfile(targetFile?: string):
  Promise<DockerFileAnalysis|undefined> {

  if (!targetFile) {
    return undefined;
  }

  const contents = await readFile(targetFile);
  const dockerfile = DockerfileParser.parse(contents);
  const from = dockerfile.getFROMs().pop();
  const runInstructions = dockerfile.getInstructions()
    .filter((instruction) => {
      return instruction.getInstruction() === 'RUN';
    })
    .map((instruction) => instruction.toString());
  const dockerfilePackages = getPackagesFromRunInstructions(runInstructions);

  let baseImage;

  if (from) {
    const fromVariables = from.getVariables();
    baseImage = from.getImage() as string;

    if (fromVariables) {
      const resolvedVariables = fromVariables.reduce(
        (resolvedVars, variable) => {
          const line = variable.getRange().start.line;
          const name = variable.getName();
          resolvedVars[name] = dockerfile.resolveVariable(name, line);
          return resolvedVars;
        }, {});

      Object.keys(resolvedVariables).forEach((variable) => {
        baseImage = baseImage.replace(
          `\$\{${variable}\}`, resolvedVariables[variable]);
      });
    }
  }

  return {
    baseImage,
    dockerfilePackages,
  };
}

async function readFile(path: string) {
  return new Promise((resolve, reject) => {
    fs.readFile(path, 'utf8', (err, data) => {
      return err ? reject(err) : resolve(data);
    });
  }) as Promise<string>;
}
