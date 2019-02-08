import { Docker } from '../docker';
import { AnalyzerPkg } from './types';
import { Output } from '../sub-process';

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
    .catch(error => {
      const stderr = error.stderr;
      if (typeof stderr === 'string' && stderr.indexOf('not found') >= 0) {
        return { stdout: '', stderr: ''};
      }
      throw error;
    })
    .then(parseOutput);
}

function parseOutput(output: Output) {
  const pkgs: AnalyzerPkg[] = [];
  for (const line of output.stdout.split('\n')) {
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
