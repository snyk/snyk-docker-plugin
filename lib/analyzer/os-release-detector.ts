import subProcess from '../sub-process';

export {
  detect,
};

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

async function detect(targetImage) {
  let osRelease = await tryOSRelease(targetImage);

  // First generic fallback
  if (!osRelease) {
    osRelease = await tryLSBRelease(targetImage);
  }

  // Fallbacks for specific older distributions
  if (!osRelease) {
    osRelease = await tryDebianVersion(targetImage);
  }

  if (!osRelease) {
    osRelease = await tryAlpineRelease(targetImage);
  }

  if (!osRelease) {
    osRelease = await tryOracleRelease(targetImage);
  }

  if (!osRelease) {
    osRelease = await tryRedHatRelease(targetImage);
  }

  if (!osRelease) {
    throw new Error('Failed to detect OS release');
  }

  // Oracle Linux identifies itself as "ol"
  if (osRelease.name === 'ol') {
    osRelease.name = 'oracle';
  }

  return osRelease;
}

async function tryOSRelease(targetImage) {
  const text = await dockerCat(targetImage, '/etc/os-release');
  if (!text) {
    return null;
  }
  const idRes = text.match(/^ID=(.+)$/m);
  if (!idRes) {
    throw new Error('Failed to parse /etc/os-release');
  }
  const name = idRes[1].replace(/"/g, '');
  const versionRes = text.match(/^VERSION_ID=(.+)$/m);
  const version = versionRes ? versionRes[1].replace(/"/g, '') : 'unstable';
  return { name, version };
}

async function tryLSBRelease(targetImage) {
  const text = await dockerCat(targetImage, '/etc/lsb-release');
  if (!text) {
    return null;
  }
  const idRes = text.match(/^DISTRIB_ID=(.+)$/m);
  const versionRes = text.match(/^DISTRIB_RELEASE=(.+)$/m);
  if (!idRes || !versionRes) {
    throw new Error('Failed to parse /etc/lsb-release');
  }
  const name = idRes[1].replace(/"/g, '').toLowerCase();
  const version = versionRes[1].replace(/"/g, '');
  return { name, version };
}

async function tryDebianVersion(targetImage) {
  let text = await dockerCat(targetImage, '/etc/debian_version');
  if (!text) {
    return null;
  }
  text = text.trim();
  if (text.length < 2) {
    throw new Error('Failed to parse /etc/debian_version');
  }
  return { name: 'debian', version: text.split('.')[0] };
}

async function tryAlpineRelease(targetImage) {
  let text = await dockerCat(targetImage, '/etc/alpine-release');
  if (!text) {
    return null;
  }
  text = text.trim();
  if (text.length < 2) {
    throw new Error('Failed to parse /etc/alpine-release');
  }
  return { name: 'alpine', version: text };
}

async function tryRedHatRelease(targetImage) {
  const text = await dockerCat(targetImage, '/etc/redhat-release');
  if (!text) {
    return null;
  }
  const idRes = text.match(/^(\S+)/m);
  const versionRes = text.match(/(\d+)\./m);
  if (!idRes || !versionRes) {
    throw new Error('Failed to parse /etc/redhat-release');
  }
  const name = idRes[1].replace(/"/g, '').toLowerCase();
  const version = versionRes[1].replace(/"/g, '');
  return { name, version };
}

async function tryOracleRelease(targetImage) {
  const text = await dockerCat(targetImage, '/etc/oracle-release');
  if (!text) {
    return null;
  }
  const idRes = text.match(/^(\S+)/m);
  const versionRes = text.match(/(\d+\.\d+)/m);
  if (!idRes || !versionRes) {
    throw new Error('Failed to parse /etc/oracle-release');
  }
  const name = idRes[1].replace(/"/g, '').toLowerCase();
  const version = versionRes[1].replace(/"/g, '');
  return { name, version };
}
