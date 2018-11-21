#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { test } from 'tap';
import * as path from 'path';

import * as dockerFile from '../../lib/docker-file';

const getDockerfileFixture = (folder: string) => path.join(
  __dirname,
  '../fixtures/dockerfiles',
  folder,
  'Dockerfile');

test('Dockerfile not supplied', async (t) => {
  t.equal(await dockerFile.getBaseImageName(), undefined, 'returns undefined');
});

test('Dockerfile not found', async (t) => {
  t.rejects(
    () => dockerFile.getBaseImageName('missing/Dockerfile'),
    new Error('ENOENT: no such file or directory, open \'missing/Dockerfile\''),
    'rejects with');
});

test('getBaseImageName for', async (t) => {
  const examples = [
    {
      description: 'a simple Dockerfile',
      fixture: 'simple',
      expected: 'ubuntu:bionic',
    },
    {
      description: 'a multi-stage Dockerfile',
      fixture: 'multi-stage',
      expected: 'alpine:latest',
    },
    {
      description: 'a from-scratch Dockerfile',
      fixture: 'from-scratch',
      expected: 'scratch',
    },
    {
      description: 'an empty Dockerfile',
      fixture: 'empty',
      expected: undefined,
    },
    {
      description: 'an invalid Dockerfile',
      fixture: 'invalid',
      expected: undefined,
    },
    {
      description: 'a Dockerfile with multiple ARGs',
      fixture: 'with-args',
      expected: 'node:dubnium',
    },
  ];
  for (const example of examples) {
    await t.test(example.description, async (t) => {
      const pathToDockerfile = getDockerfileFixture(example.fixture);
      const actual = await dockerFile.getBaseImageName(pathToDockerfile);
      t.equal(actual, example.expected, `returns ${example.expected}`);
    });
  }
});
