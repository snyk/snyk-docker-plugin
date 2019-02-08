#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import { test } from 'tap';
import * as sinon from 'sinon';

import * as subProcess from '../../../lib/sub-process';
import * as imageInspector from '../../../lib/analyzer/image-inspector';

test('image id', async t => {
  const expectedId = 'sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b393902f';
  const expectedLayers =
  ['sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b3939021',
  'sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b3939022',
  'sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b3939023'];

  const stubbedData = [{
    Id: expectedId,
    RootFS: {
      Layers: expectedLayers,
    },
    MoreStuff: 'stuff',
  }];

  const execStub = sinon.stub(subProcess, 'execute');
  execStub.withArgs('docker', ['inspect', 'alpine:2.6'])
    .resolves({stdout: JSON.stringify(stubbedData), stderr: ''});
  t.teardown(() => execStub.restore());

  const imageData = await imageInspector.detect('alpine:2.6');
  t.same(imageData.Id, expectedId, 'id as expected');
  t.same(imageData.RootFS.Layers, expectedLayers, 'layers as expected');
});
