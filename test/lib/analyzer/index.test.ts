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
import * as analyzer from '../../../lib/analyzer';
import * as imageIdDetector from '../../../lib/analyzer/image-id-detector';

const readOsFixtureFile = (...from) => fs.readFileSync(
  path.join(__dirname, '../../fixtures/os', ...from), 'utf8');

test('analyzer', async t => {

  const examples = {
    'alpine:2.6': {
      dir: 'alpine_2_6_6',
    },
  };

  const execStub = sinon.stub(subProcess, 'execute');

  // Stub Docker cat file
  execStub.withArgs('docker', [
    'run', '--rm', sinon.match.any, 'cat', sinon.match.any,
  ])
    .callsFake(async (docker, [run, rm, image, cat, file]) => {
      try {
        const example = examples[image];
        return readOsFixtureFile(example.dir, 'fs', file);
      } catch {
        throw `cat: ${file}: No such file or directory`;
      }
    });

  // Stub Docker `run rpm` command
  execStub.withArgs('docker', [
    'run',
    '--rm',
    sinon.match.any,
    'rpm',
    '--nodigest',
    '--nosignature',
    '-qa',
    '--qf',
    '"%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SIZE}\n"',
  ])
    .callsFake(async (docker, [run, rm, image]) => {
      try {
        const example = examples[image];
        return readOsFixtureFile(example.dir, 'rpm-output.txt');
      } catch {
        throw `docker: Error response from daemon: OCI runtime create failed: container_linux.go:348: starting container process caused "exec: \"rpm\": executable file not found in $PATH": unknown.`;
      }
    });

  const imageIdStub = sinon.stub(imageIdDetector, 'detect')
    .resolves('sha256:fake');

  t.teardown(() => {
    execStub.restore();
    imageIdStub.restore();
  });

  for (const targetImage of Object.keys(examples)) {
    const example = examples[targetImage];
    const expectation = JSON.parse(
      readOsFixtureFile(example.dir, 'analyzer-expect.json'));

    const actual = await analyzer.analyze(targetImage);
    t.same(actual, expectation);
  }
});
