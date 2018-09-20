import * as fs from 'fs';
import * as dockerFileParser from 'docker-file-parser';

export { getBaseImageName };

async function getBaseImageName(targetFile?: string):
  Promise<string|undefined> {

  if (!targetFile) {
    return undefined;
  }

  const contents = await readFile(targetFile);
  const commands = dockerFileParser.parse(contents);
  const fromCommands = commands.filter(command => command.name === 'FROM');
  const finalFrom = fromCommands.pop();

  return finalFrom ? String(finalFrom.args) : undefined;
}

async function readFile(path: string) {
  return new Promise((resolve, reject) => {
    fs.readFile(path, 'utf8', (err, data) => {
      return err ? reject(err) : resolve(data);
    });
  }) as Promise<string>;
}
