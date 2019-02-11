import { Docker, DockerOptions } from '../docker';
import { OSRelease } from './types';
import { TextDecoder } from 'util';

export {
  detect,
};

async function detect(targetImage: string, options?: DockerOptions):
  Promise<OSRelease> {
  const docker = new Docker(targetImage, options);

  let osRelease = await tryOSRelease(docker);

  // First generic fallback
  if (!osRelease) {
    osRelease = await tryLSBRelease(docker);
  }

  // Fallbacks for specific older distributions
  if (!osRelease) {
    osRelease = await tryDebianVersion(docker);
  }

  if (!osRelease) {
    osRelease = await tryAlpineRelease(docker);
  }

  if (!osRelease) {
    osRelease = await tryOracleRelease(docker);
  }

  if (!osRelease) {
    osRelease = await tryRedHatRelease(docker);
  }

  if (!osRelease) {
    throw new Error('Failed to detect OS release');
  }

  // Oracle Linux identifies itself as "ol"
  if (osRelease.name.trim() === 'ol') {
    osRelease.name = 'oracle';
  }

  return osRelease;
}

async function tryOSRelease(docker: Docker): Promise<OSRelease|null> {
  const text = await tryRelease(docker, '/etc/os-release');
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

async function tryLSBRelease(docker: Docker): Promise<OSRelease|null> {
  const text = await tryRelease(docker, '/etc/lsb-release');
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

async function tryDebianVersion(docker: Docker): Promise<OSRelease|null> {
  let text = await tryRelease(docker, '/etc/debian_version');
  if (!text) {
    return null;
  }
  text = text.trim();
  if (text.length < 2) {
    throw new Error('Failed to parse /etc/debian_version');
  }
  return { name: 'debian', version: text.split('.')[0] };
}

async function tryAlpineRelease(docker: Docker): Promise<OSRelease|null> {
  let text = await tryRelease(docker, '/etc/alpine-release');
  if (!text) {
    return null;
  }
  text = text.trim();
  if (text.length < 2) {
    throw new Error('Failed to parse /etc/alpine-release');
  }
  return { name: 'alpine', version: text };
}

async function tryRedHatRelease(docker: Docker): Promise<OSRelease|null> {
  const text = await tryRelease(docker, '/etc/redhat-release');

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

async function tryOracleRelease(docker: Docker): Promise<OSRelease|null> {
  const text = await tryRelease(docker, '/etc/oracle-release');
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

async function tryRelease(docker: Docker, release: string): Promise<string> {
  try {
    return (await docker.catSafe(release)).stdout;
  } catch (error) {
    throw new Error(error.stderr);
  }
}
