import { Docker } from '../docker';
import { AnalyzerPkg } from './types';

export {
  analyze,
};

async function analyze(targetImage: string) {
  const pkgs = await getPackages(targetImage);
  return {
    Image: targetImage,
    AnalyzeType: 'Rpm',
    Analysis: pkgs,
  };
}

function getPackages(targetImage: string) {
  return new Docker(targetImage).run('rpm', [
    '--nodigest',
    '--nosignature',
    '-qa',
    '--qf',
    '"%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SIZE}\n"',
  ])
    .catch(stderr => {
      if (typeof stderr === 'string' && stderr.indexOf('not found') >= 0) {
        return '';
      }
      throw new Error(stderr);
    })
    .then(parseOutput);
}

function parseOutput(text: string) {
  const pkgs: AnalyzerPkg[] = [];
  for (const line of text.split('\n')) {
    parseLine(line, pkgs);
  }
  return pkgs;
}

function parseLine(text: string, pkgs: AnalyzerPkg[]) {
  const [name, version, size] = text.split('\t');
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
