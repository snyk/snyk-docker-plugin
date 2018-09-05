import * as subProcess from '../sub-process';

export {
  analyze,
};

async function analyze(targetImage) {
  const pkgs = await getPackages(targetImage);
  return {
    Image: targetImage,
    AnalyzeType: 'Rpm',
    Analysis: pkgs,
  };
}

function getPackages(targetImage) {
  return subProcess.execute('docker', [
    'run',
    '--rm',
    targetImage,
    'rpm',
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

function parseOutput(text) {
  const pkgs = [];
  for (const line of text.split('\n')) {
    parseLine(line, pkgs);
  }
  return pkgs;
}

function parseLine(text: string, pkgs) {
  const [name, version, size] = text.split('\t');
  if (name && version && size) {
    const pkg = {
      Name: name,
      Version: version,
      Source: null,
      Provides: [],
      Deps: {},
      AutoInstalled: null,
    };
    pkgs.push(pkg);
  }
}
