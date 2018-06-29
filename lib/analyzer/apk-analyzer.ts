import subProcess from '../sub-process';

export {
  analyze,
};

function analyze(targetImage) {
  return getPackages(targetImage)
    .then(pkgs => ({
      Image: targetImage,
      AnalyzeType: 'Apk',
      Analysis: pkgs,
    }));
}

function getPackages(targetImage) {
  return subProcess.execute('docker', [
    'run', '--rm', targetImage, 'cat', '/lib/apk/db/installed',
  ])
    .catch(stderr => {
      if (typeof stderr === 'string' && stderr.indexOf('No such file') >= 0) {
        return '';
      }
      throw new Error(stderr);
    })
    .then(parseFile);
}

function parseFile(text) {
  const pkgs = [];
  let curPkg = null;
  for (const line of text.split('\n')) {
    curPkg = parseLine(line, curPkg, pkgs);
  }
  return pkgs;
}

function parseLine(text, curPkg, pkgs) {
  const key = text.charAt(0);
  const value = text.substr(2);
  switch (key) {
    case 'P': // Package
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
    case 'V': // Version
      curPkg.Version = value;
      break;
    case 'p': // Provides
      for (let name of value.split(' ')) {
        name = name.split('=')[0];
        curPkg.Provides.push(name);
      }
      break;
    case 'r': // Depends
    case 'D': // Depends
      // tslint:disable-next-line:no-duplicate-variable
      for (let name of value.split(' ')) {
        if (name.charAt(0) !== '!') {
          name = name.split('=')[0];
          curPkg.Deps[name] = true;
        }
      }
      break;
  }
  return curPkg;
}
