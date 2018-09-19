import * as fs from 'fs';

export { getBaseImageName };

async function getBaseImageName(targetFile?: string):
  Promise<string|undefined> {

  if (!targetFile) {
    return undefined;
  }

  const contents = await readFile(targetFile);

  const results: string[] = [];
  const FROM_RE = /^FROM ([^\s]+)[\s\S]*?$/gim;
  let match: RegExpExecArray|null;
  while (match = FROM_RE.exec(contents)) {
    results.push(match[1]);
  }

  return results.length ? results.pop() : undefined;
}

async function readFile(path: string) {
  return new Promise((resolve, reject) => {
    fs.readFile(path, 'utf8', (err, data) => {
      return err ? reject(err) : resolve(data);
    });
  }) as Promise<string>;
}
