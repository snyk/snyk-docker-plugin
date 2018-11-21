import * as fs from 'fs';
import { DockerfileParser } from 'dockerfile-ast';

export { getBaseImageName };

async function getBaseImageName(targetFile?: string):
  Promise<string|undefined> {

  if (!targetFile) {
    return undefined;
  }

  const contents = await readFile(targetFile);
  const dockerfile = DockerfileParser.parse(contents);
  const from = dockerfile.getFROMs().pop();

  if (!from) {
    return undefined;
  }

  const fromVariables = from.getVariables();
  let baseImage = from.getImage() as string;

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

  return baseImage;
}

async function readFile(path: string) {
  return new Promise((resolve, reject) => {
    fs.readFile(path, 'utf8', (err, data) => {
      return err ? reject(err) : resolve(data);
    });
  }) as Promise<string>;
}
