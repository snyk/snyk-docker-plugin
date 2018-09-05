#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import { test } from 'tap';
import * as sinon from 'sinon';

import * as subProcess from '../../../lib/sub-process';
import * as imageIdDetector from '../../../lib/analyzer/image-id-detector';

test('image id', async t => {
  const expectedId = 'sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b393902f';
  const execStub = sinon.stub(subProcess, 'execute');
  execStub.withArgs('docker', ['inspect', 'alpine:2.6'])
    .resolves(`[{
        "Id": "${expectedId}",
        "MoreStuff": "stuff"
      }]`);
  t.teardown(() => execStub.restore());

  const actual = await imageIdDetector.detect('alpine:2.6');
  t.same(actual, expectedId, 'id as expected');
});
