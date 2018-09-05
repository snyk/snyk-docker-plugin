import * as subProcess from '../sub-process';

export {
  analyze,
};

async function analyze(targetImage) {
  const dpkgFile = await dockerCat(targetImage, '/var/lib/dpkg/status');
  const pkgs = parseDpkgFile(dpkgFile);

  const extFile = await dockerCat(targetImage, '/var/lib/apt/extended_states');
  if (extFile) {
    setAutoInstalledPackages(extFile, pkgs);
  }

  return {
    Image: targetImage,
    AnalyzeType: 'Apt',
    Analysis: pkgs,
  };
}

async function dockerCat(targetImage, file): Promise<string> {
  try {
    return await subProcess.execute('docker', [
      'run', '--rm', targetImage, 'cat', file,
    ]);
  } catch (stderr) {
    if (typeof stderr === 'string' && stderr.indexOf('No such file') >= 0) {
      return '';
    }
    throw new Error(stderr);
  }
}

function parseDpkgFile(text) {
  const pkgs = [];
  let curPkg = null;
  for (const line of text.split('\n')) {
    curPkg = parseDpkgLine(line, curPkg, pkgs);
  }
  return pkgs;
}

function parseDpkgLine(text, curPkg, pkgs) {
  const [key, value] = text.split(': ');
  switch (key) {
    case 'Package':
      curPkg = {
        Name: value,
        Version: null,
        Source: null,
        Provides: [],
        Deps: {},
        AutoInstalled: null,
      };
      pkgs.push(curPkg);
      break;
    case 'Version':
      curPkg.Version = value;
      break;
    case 'Source':
      curPkg.Source = value.trim().split(' ')[0];
      break;
    case 'Provides':
      for (let name of value.split(',')) {
        name = name.trim().split(' ')[0];
        curPkg.Provides.push(name);
      }
      break;
    case 'Pre-Depends':
    case 'Depends':
      for (const depElem of value.split(',')) {
        for (let name of depElem.split('|')) {
          name = name.trim().split(' ')[0];
          curPkg.Deps[name] = true;
        }
      }
      break;
  }
  return curPkg;
}

function setAutoInstalledPackages(text, pkgs) {
  const autoPkgs = parseExtFile(text);
  for (const pkg of pkgs) {
    if (autoPkgs[pkg.Name]) {
      pkg.AutoInstalled = true;
    }
  }
}

function parseExtFile(text) {
  const pkgMap = {};
  let curPkgName = null;
  for (const line of text.split('\n')) {
    curPkgName = parseExtLine(line, curPkgName, pkgMap);
  }
  return pkgMap;
}

function parseExtLine(text, curPkgName, pkgMap) {
  const [key, value] = text.split(': ');
  switch (key) {
    case 'Package':
      curPkgName = value;
      break;
    case 'Auto-Installed':
      if (parseInt(value, 10) === 1) {
        pkgMap[curPkgName] = true;
      }
      break;
  }
  return curPkgName;
}
