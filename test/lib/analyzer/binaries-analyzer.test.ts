#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import { test } from 'tap';
import * as sinon from 'sinon';

import * as subProcess from '../../../lib/sub-process';
import * as analyzer from '../../../lib/analyzer/binaries-analyzer';

test('analyze', async t => {

  const examples = [
    {
      description: 'no Node in image',
      targetImage: 'alpine:2.6',
      binariesOutputLines: [''],
      expectedBinaries: [ ],
    },
    {
      description: 'bogus output',
      targetImage: 'node:6.15.1',
      binariesOutputLines: ['bogus.version.6'],
      expectedBinaries: [ ],
    },
    {
      description: 'Node is in image',
      targetImage: 'node:6.15.1',
      binariesOutputLines: ['v6.15.1'],
      expectedBinaries:
      [
        { name: 'node', version: '6.15.1' },
      ],
    },
  ];

  for (const example of examples) {
    console.log(example.description)
    await t.test(example.description, async t => {
      const execStub = sinon.stub(subProcess, 'execute');
      execStub.withArgs('docker', [
        'run', '--rm', '--entrypoint', '""', '--network', 'none',
        sinon.match.any,
        'node',
        '--version',
      ]).resolves(example.binariesOutputLines.join('\n'));

      t.teardown(() => execStub.restore());

      const actual = await analyzer.analyze(example.targetImage);

      t.same(actual, {
        Image: example.targetImage,
        AnalyzeType: 'binaries',
        Analysis: example.expectedBinaries,
      });
    });
  }
});
