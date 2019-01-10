#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { test } from 'tap';
import * as sinon from 'sinon';
import * as fs from 'fs';
import * as path from 'path';

import * as subProcess from '../../../lib/sub-process';
import * as analyzer from '../../../lib/analyzer';
import * as imageInspector from '../../../lib/analyzer/image-inspector';

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
    'run', '--rm', '--entrypoint', '""', '--network', 'none',
    sinon.match.any, 'cat', sinon.match.any,
  ])
    .callsFake(async (docker,
      [run, rm, entry, empty, network, none, image, cat, file]) => {
      try {
        const example = examples[image];
        return readOsFixtureFile(example.dir, 'fs', file);
      } catch {
        // tslint:disable-next-line:no-string-throw
        throw `cat: ${file}: No such file or directory`;
      }
    });

  // Stub Docker `run rpm` command
  execStub.withArgs('docker', [
    'run', '--rm', '--entrypoint', '""', '--network', 'none',
    sinon.match.any,
    'rpm',
    '--nodigest',
    '--nosignature',
    '-qa',
    '--qf',
    '"%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SIZE}\n"',
  ])
    .callsFake(async (docker,
      [run, rm, entry, empty, network, none, image]) => {
      try {
        const example = examples[image];
        return readOsFixtureFile(example.dir, 'rpm-output.txt');
      } catch {
        // tslint:disable-next-line:no-string-throw
        throw `docker: Error response from daemon: OCI runtime \
        create failed: container_linux.go:348: starting container process\
        caused "exec: \"rpm\": executable file not found in $PATH": unknown.`;
      }
    });

  // Stub Docker `node --version` command
    execStub.withArgs('docker', [
      'run', '--rm', '--entrypoint', '""', '--network', 'none',
      sinon.match.any,
      'node',
      '--version',
    ])
      .callsFake(async (docker,
        [run, rm, entry, empty, network, none, image]) => {
        try {
          const example = examples[image];
          return readOsFixtureFile(example.dir, 'node-version.txt');
        } catch {
          // tslint:disable-next-line:no-string-throw
          throw 'docker: Error running `docker node --version`';
        }
      });

  // Stub Docker `java -version` command
    execStub.withArgs('docker', [
      'run', '--rm', '--entrypoint', '""', '--network', 'none',
      sinon.match.any,
      'java',
      '-version',
    ])
      .callsFake(async (docker,
        [run, rm, entry, empty, network, none, image]) => {
        try {
          const example = examples[image];
          return readOsFixtureFile(example.dir, 'openjdk-jre-version.txt');
        } catch {
          // tslint:disable-next-line:no-string-throw
          throw 'docker: Error running `docker java -version`';
        }
      });

  const expectedId = 'sha256:fake';
  const expectedLayers = [
    'sha256:fake1',
    'sha256:fake2',
    'sha256:fake3',
  ];

  const stubbedData = {
    Id: expectedId,
    RootFS: {
      Layers: expectedLayers,
    },
    MoreStuff: 'stuff',
  };
  const imageInspectorStub = sinon.stub(imageInspector, 'detect')
    .resolves(stubbedData);

  t.teardown(() => {
    execStub.restore();
    imageInspectorStub.restore();
  });

  for (const targetImage of Object.keys(examples)) {
    const example = examples[targetImage];
    const expectation = JSON.parse(
      readOsFixtureFile(example.dir, 'analyzer-expect.json'));

    const actual = await analyzer.analyze(targetImage);
    t.same(actual, expectation);
  }
});
