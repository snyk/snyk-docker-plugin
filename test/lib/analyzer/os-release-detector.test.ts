#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:no-string-throw

import { test } from 'tap';
import * as sinon from 'sinon';
import * as fs from 'fs';
import * as path from 'path';

import * as subProcess from '../../../lib/sub-process';
import * as osReleaseDetector from '../../../lib/analyzer/os-release-detector';

const readOsFixtureFile = (...from) => fs.readFileSync(
  path.join(__dirname, '../../fixtures/os', ...from), 'utf8');

test('os release detection', async t => {

  const examples = {
    'alpine:2.6': {
      dir: 'alpine_2_6_6',
      expected: { name: 'alpine', version: '2.6.6' },
      notes: 'uses /etc/alpine-release',
    },
    'alpine:3.7': {
      dir: 'alpine_3_7_0',
      expected: { name: 'alpine', version: '3.7.0' },
      notes: 'uses /etc/os-release',
    },
    'centos:5': {
      dir: 'centos_5',
      expected: { name: 'centos', version: '5' },
      notes: 'uses /etc/redhat-release',
    },
    'centos:6': {
      dir: 'centos_6',
      expected: { name: 'centos', version: '6' },
      notes: 'uses /etc/redhat-release',
    },
    'centos:7': {
      dir: 'centos_7',
      expected: { name: 'centos', version: '7' },
      notes: 'uses /etc/os-release',
    },
    'debian:6': {
      dir: 'debian_6',
      expected: { name: 'debian', version: '6' },
      notes: 'uses /etc/debian_version',
    },
    'debian:7': {
      dir: 'debian_7',
      expected: { name: 'debian', version: '7' },
      notes: 'uses /etc/os-release',
    },
    'debian:8': {
      dir: 'debian_8',
      expected: { name: 'debian', version: '8' },
      notes: 'uses /etc/os-release',
    },
    'debian:9': {
      dir: 'debian_9',
      expected: { name: 'debian', version: '9' },
      notes: 'uses /etc/os-release',
    },
    'debian:unstable': {
      dir: 'debian_unstable',
      expected: { name: 'debian', version: 'unstable' },
      notes: 'uses /etc/os-release',
    },
    'oracle:5.11': {
      dir: 'oraclelinux_5_11',
      expected: { name: 'oracle', version: '5.11' },
      notes: 'uses /etc/oracle-release',
    },
    'oracle:6.9': {
      dir: 'oraclelinux_6_9',
      expected: { name: 'oracle', version: '6.9' },
      notes: 'uses /etc/os-release',
    },
    'oracle:7.5': {
      dir: 'oraclelinux_7_5',
      expected: { name: 'oracle', version: '7.5' },
      notes: 'uses /etc/os-release',
    },
    'ubuntu:10.04': {
      dir: 'ubuntu_10_04',
      expected: { name: 'ubuntu', version: '10.04' },
      notes: 'uses /etc/lsb-release',
    },
    'ubuntu:12.04': {
      dir: 'ubuntu_12_04',
      expected: { name: 'ubuntu', version: '12.04' },
      notes: 'uses /etc/os-release',
    },
    'ubuntu:14.04': {
      dir: 'ubuntu_14_04',
      expected: { name: 'ubuntu', version: '14.04' },
      notes: 'uses /etc/os-release',
    },
    'ubuntu:16.04': {
      dir: 'ubuntu_16_04',
      expected: { name: 'ubuntu', version: '16.04' },
      notes: 'uses /etc/os-release',
    },
    'ubuntu:18.04': {
      dir: 'ubuntu_18_04',
      expected: { name: 'ubuntu', version: '18.04' },
      notes: 'uses /etc/os-release',
    },
  };

  const execStub = sinon.stub(subProcess, 'execute');
  execStub.withArgs('docker', [
    'run', '--rm', '--entrypoint', '""', '--network', 'none',
    sinon.match.any, 'cat', sinon.match.any,
  ])
    .callsFake(async (docker, [run, rm, entry, empty, network, none, image, cat, file]) => {
      try {
        const example = examples[image];
        return readOsFixtureFile(example.dir, 'fs', file);
      } catch {
        throw `cat: ${file}: No such file or directory`;
      }
    });
  t.teardown(() => execStub.restore());

  for (const targetImage of Object.keys(examples)) {
    const example = examples[targetImage];
    const actual = await osReleaseDetector.detect(targetImage);
    t.same(actual, example.expected, targetImage);
  }
});

test('failed detection', async t => {

  const examples = {
    'unexpected:unexpected': {
      dir: 'missing',
      expectedError: 'Failed to detect OS release',
    },
    'os-release:corrupt': {
      dir: 'os_release_corrupt',
      expectedError: 'Failed to parse /etc/os-release',
    },
    'lsb-release:corrupt': {
      dir: 'lsb_release_corrupt',
      expectedError: 'Failed to parse /etc/lsb-release',
    },
    'debian_version:corrupt': {
      dir: 'debian_version_corrupt',
      expectedError: 'Failed to parse /etc/debian_version',
    },
    'alpine-release:corrupt': {
      dir: 'alpine_release_corrupt',
      expectedError: 'Failed to parse /etc/alpine-release',
    },
  };

  const execStub = sinon.stub(subProcess, 'execute');
  execStub.withArgs('docker', [
    'run', '--rm', '--entrypoint', '""', '--network', 'none',
    sinon.match.any, 'cat', sinon.match.any,
  ])
    .callsFake(async (docker, [run, rm, entry, empty, network, none, image, cat, file]) => {
      try {
        const example = examples[image];
        return readOsFixtureFile(example.dir, 'fs', file);
      } catch {
        throw `cat: ${file}: No such file or directory`;
      }
    });
  t.teardown(() => execStub.restore());

  for (const targetImage of Object.keys(examples)) {
    const example = examples[targetImage];
    try {
      await osReleaseDetector.detect(targetImage);
      t.fail('should have thrown');
    } catch (error) {
      t.same(error.message, example.expectedError, example.expectedError);
    }
  }
});
