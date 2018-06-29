#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import { test } from 'tap';
import sinon from 'sinon';

import subProcess from '../../../lib/sub-process';
import * as analyzer from '../../../lib/analyzer/apk-analyzer';

test('analyze', async t => {
  const defaultPkgProps = {
    Name: null,
    Version: null,
    Source: null,
    Provides: [],
    Deps: {},
    AutoInstalled: null,
  };

  const examples = [
    {
      description: 'Not applicable line',
      manifestLines: ['Garbage: garbage info'],
      expectedPackages: [],
    },
    {
      description: 'Package line',
      manifestLines: ['P:La-Croix'],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix' },
      ],
    },
    {
      description: 'Package and version',
      manifestLines: [
        'P:La-Croix',
        'V:Lime',
      ],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime' },
      ],
    },
    {
      description: 'Package and version with deb release info',
      manifestLines: [
        'P:La-Croix',
        'V:Lime+extra_lime',
      ],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime+extra_lime' },
      ],
    },
    {
      description: 'Package and version with stuff in between',
      manifestLines: [
        'P:La-Croix',
        'Foo:Bar',
        'Baz:Zip',
        'V:Lime',
      ],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime' },
      ],
    },
    {
      description: 'New package block creates new package',
      manifestLines: [
        'P:La-Croix',
        'V:Lime',
        'P:Foo',
        'V:Bar',
      ],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime' },
        { ...defaultPkgProps, Name: 'Foo', Version: 'Bar' },
      ],
    },
    {
      description: 'Depends on one package',
      manifestLines: [
        'P:libc-utils',
        'V:0.7.1-r0',
        'D:musl-utils',
      ],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'libc-utils',
          Version: '0.7.1-r0',
          Deps: {
            'musl-utils': true,
          },
        },
      ],
    },
    {
      description: 'Depends on multiple packages',
      manifestLines: [
        'P:libc-utils',
        'V:0.7.1-r0',
        'D:!uclibc-utils scanelf musl=1.1.18-r3 so:libc.musl-x86_64.so.1',
        'r:libiconv uclibc-utils',
      ],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'libc-utils',
          Version: '0.7.1-r0',
          Deps: {
            'scanelf': true,
            'musl': true,
            'so:libc.musl-x86_64.so.1': true,
            'libiconv': true,
            'uclibc-utils': true,
          },
        },
      ],
    },
    {
      description: 'Provides',
      manifestLines: [
        'P:libc',
        'V:0.9.33.2-r22',
        'p:so:ld64-uClibc.so.0.9.32=0 so:libc.so.0.9.32=0 so:libcrypt.so.0.9.32=0',
      ],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'libc',
          Version: '0.9.33.2-r22',
          Provides: [
            'so:ld64-uClibc.so.0.9.32',
            'so:libc.so.0.9.32',
            'so:libcrypt.so.0.9.32',
          ],
        },
      ],
    },
  ];

  for (const example of examples) {
    await t.test(example.description, async t => {
      const execStub = sinon.stub(subProcess, 'execute');

      execStub.withArgs('docker', [
        'run', '--rm', sinon.match.any, 'cat', '/lib/apk/db/installed',
      ]).resolves(example.manifestLines.join('\n'));

      t.teardown(() => execStub.restore());

      const actual = await analyzer.analyze('alpine:2.6');

      t.same(actual, {
        Image: 'alpine:2.6',
        AnalyzeType: 'Apk',
        Analysis: example.expectedPackages,
      });
    });
  }
});
