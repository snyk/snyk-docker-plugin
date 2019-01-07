import { Docker } from '../docker';
import { AnalyzerPkg } from './types';

const DELIM: string = '\t';
const NO_PKG: string = 'no package provides ';

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
  // information can be found at:
  // git log --all --grep='feat: add non-direct dependencies for rpm analyzer'
  return new Docker(targetImage).run('rpm', [
    '--nodigest',
    '--nosignature',
    '-qaR',
    '--qf',
    '"%{NAME}' + DELIM + '%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n"',
  ])
    .catch(stderr => {
      if (typeof stderr === 'string' && stderr.indexOf('not found') >= 0) {
        return '';
      }
      throw new Error(stderr);
    })
    .then(stdout => {
      if (!stdout) {
        return [];
      }
      return parseRequirements(targetImage, stdout);
    });
}

function parseRequirements(targetImage: string, reqText: string) {
  const whatProvidesText: string = reqText
    .trim()
    .split('\n')
    .map(line => {
      if (line.includes(' ')) {
        line = line.split(' ')[0];
      }
      return '"' + line + '"';
    })
    .join(' ');

    return new Docker(targetImage).run('rpm', [
      '--nodigest',
      '--nosignature',
      '-q',
      '--qf',
      '"%{NAME}\n"',
      '--whatprovides',
      whatProvidesText,
    ])
      .catch(stderr => {
        if (typeof stderr === 'string' && stderr.includes(NO_PKG)) {
          return stderr;
        }
        throw new Error(stderr);
    })
      .then(parseProviders);
}

function parseProviders(providersText: string) {
  const pkgs: AnalyzerPkg[] = [];
  let curPkg: any = null;

  const providers: string[] = providersText.trim().split('\n');
  // packages appear after their dependencies; iterate backwards
  for (let i = providers.length - 1; i >= 0; i--) {
    curPkg = parseProviderLine(providers[i], curPkg, pkgs);
  }
  return pkgs;
}

function parseProviderLine(line: string, curPkg: any, pkgs: AnalyzerPkg[]) {
  if (line.includes(DELIM)) {
    const [pkg, version] = line.replace(NO_PKG, '').split(DELIM);
    curPkg = {
      Name: pkg,
      Version: version,
      Source: undefined,
      Provides: [],
      Deps: {},
      AutoInstalled: undefined,
    };
    pkgs.push(curPkg);
    return curPkg;
  }
  if (!line.includes(NO_PKG) && line !== curPkg.Name) {
    curPkg.Deps[line] = true;
  }
  return curPkg;
}
