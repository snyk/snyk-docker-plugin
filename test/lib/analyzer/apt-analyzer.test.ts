#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import { test } from 'tap';
import * as sinon from 'sinon';

import * as subProcess from '../../../lib/sub-process';
import * as analyzer from '../../../lib/analyzer/apt-analyzer';

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
      dpkgManifestLines: ['Garbage: garbage info'],
      extManifestLines: [],
      expectedPackages: [],
    },
    {
      description: 'Package line',
      dpkgManifestLines: ['Package: La-Croix'],
      extManifestLines: [],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix' },
      ],
    },
    {
      description: 'Package and version',
      dpkgManifestLines: [
        'Package: La-Croix',
        'Version: Lime',
      ],
      extManifestLines: [],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime' },
      ],
    },
    {
      description: 'Package and version with deb release info',
      dpkgManifestLines: [
        'Package: La-Croix',
        'Version: Lime+extra_lime',
      ],
      extManifestLines: [],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime+extra_lime' },
      ],
    },
    {
      description: 'Package and version with stuff in between',
      dpkgManifestLines: [
        'Package: La-Croix',
        'Foo: Bar',
        'Baz: Zip',
        'Version: Lime',
      ],
      extManifestLines: [],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime' },
      ],
    },
    {
      description: 'New package block creates new package',
      dpkgManifestLines: [
        'Package: La-Croix',
        'Version: Lime',
        'Package: Foo',
        'Version: Bar',
      ],
      extManifestLines: [],
      expectedPackages: [
        { ...defaultPkgProps, Name: 'La-Croix', Version: 'Lime' },
        { ...defaultPkgProps, Name: 'Foo', Version: 'Bar' },
      ],
    },
    {
      description: 'Depends on one package',
      dpkgManifestLines: [
        'Package: libc-utils',
        'Version: 0.7.1-r0',
        'Depends: musl-utils',
      ],
      extManifestLines: [],
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
      dpkgManifestLines: [
        'Package: libc-utils',
        'Version: 0.7.1-r0',
        'Depends: libtinfo5 (= 5.9+20140913-1+deb8u2), libc6 (>= 2.15), libc6-dev | libc-dev',
      ],
      extManifestLines: [],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'libc-utils',
          Version: '0.7.1-r0',
          Deps: {
            'libtinfo5': true,
            'libc6': true,
            'libc6-dev': true,
            'libc-dev': true,
          },
        },
      ],
    },
    {
      description: 'Pre-Depends line after Depends',
      dpkgManifestLines: [
        'Package: libncurses5',
        'Version: 5.7+20090803-2ubuntu3',
        'Depends: libtinfo5, libc6',
        'Pre-Depends: multiarch-support, libtinfo5 (>= 5.9-3)',
      ],
      extManifestLines: [],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'libncurses5',
          Version: '5.7+20090803-2ubuntu3',
          Deps: {
            'libtinfo5': true,
            'libc6': true,
            'multiarch-support': true,
          },
        },
      ],
    },
    {
      description: 'Depends',
      dpkgManifestLines: [
        'Package: nginx',
        'Version: 1.13.10-1~stretch',
        'Depends: init-system-helpers (>= 1.18~), libc6 (>= 2.17), libpcre3, libssl1.1 (>= 1.1.0), zlib1g (>= 1:1.1.4), lsb-base (>= 3.0-6), adduser',
      ],
      extManifestLines: [],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'nginx',
          Version: '1.13.10-1~stretch',
          Deps: {
            'init-system-helpers': true,
            'libc6': true,
            'libpcre3': true,
            'libssl1.1': true,
            'zlib1g': true,
            'lsb-base': true,
            'adduser': true,
          },
        },
      ],
    },
    {
      description: 'Provides',
      dpkgManifestLines: [
        'Package: libc',
        'Version: 0.9.33.2-r22',
        'Provides: libpng-dev, libpng12-0-dev, libpng3-dev',
      ],
      extManifestLines: [],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'libc',
          Version: '0.9.33.2-r22',
          Provides: [
            'libpng-dev',
            'libpng12-0-dev',
            'libpng3-dev',
          ],
        },
      ],
    },
    {
      description: 'Source',
      dpkgManifestLines: [
        'Package: zlib1g',
        'Source: libz1',
      ],
      extManifestLines: [],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'zlib1g',
          Source: 'libz1',
        },
      ],
    },
    {
      description: 'Missing var/lib/apt/extended_states',
      dpkgManifestLines: [
        'Package: pac1',
        'Installed-Size: 123',
        'info: other stuff',
        'Version: 1.0',
        '',
        'Package: pac2',
        'info: more other stuff',
        'Provides: the-pac',
        'Version: 2.0',
        '',
        'Package: pac3',
        'Installed-Size: 123',
        'Source: pac_ng',
        'Version: 3.0',
        'Depends: pac1 (>= 0.1), libc6 | libc',
        'Pre-Depends: libc, debconf',
        'info: again other stuff',
        '',
        'Package: pac4',
        'Installed-Size: 238',
        'Source: pac4_ng (2.29.2-1+deb9u1)',
        'Version: 1:2.29.2-1+deb9u1',
        'info: again other stuff',
      ],
      extManifestLines: [],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'pac1',
          Version: '1.0',
        },
        {
          ...defaultPkgProps,
          Name: 'pac2',
          Version: '2.0',
          Provides: ['the-pac'],
        },
        {
          ...defaultPkgProps,
          Name: 'pac3',
          Version: '3.0',
          Source: 'pac_ng',
          Deps: {
            pac1: true,
            libc6: true,
            libc: true,
            debconf: true,
          },
        },
        {
          ...defaultPkgProps,
          Name: 'pac4',
          Version: '1:2.29.2-1+deb9u1',
          Source: 'pac4_ng',
        },
      ],
    },
    {
      description: 'With var/lib/apt/extended_states',
      dpkgManifestLines: [
        'Package: pac1',
        'Installed-Size: 123',
        'info: other stuff',
        'Version: 1.0',
        '',
        'Package: pac2',
        'info: more other stuff',
        'Provides: the-pac',
        'Version: 2.0',
        '',
        'Package: pac3',
        'Installed-Size: 123',
        'Source: pac_ng',
        'Version: 3.0',
        'Depends: pac1 (>= 0.1), libc6 | libc',
        'Pre-Depends: libc, debconf',
        'info: again other stuff',
        '',
        'Package: pac4',
        'Installed-Size: 238',
        'Source: pac4_ng (2.29.2-1+deb9u1)',
        'Version: 1:2.29.2-1+deb9u1',
        'info: again other stuff',
      ],
      extManifestLines: [
        'Package: pac2',
        'Architecture: amd64',
        'Auto-Installed: 1',
        '',
        'Package: pac1',
        'Architecture: amd64',
        'Auto-Installed: 0',
        '',
        'Package: paca-paca',
        'Architecture: amd64',
        'Auto-Installed: 1',
      ],
      expectedPackages: [
        {
          ...defaultPkgProps,
          Name: 'pac1',
          Version: '1.0',
        },
        {
          ...defaultPkgProps,
          Name: 'pac2',
          Version: '2.0',
          Provides: ['the-pac'],
          AutoInstalled: true,
        },
        {
          ...defaultPkgProps,
          Name: 'pac3',
          Version: '3.0',
          Source: 'pac_ng',
          Deps: {
            pac1: true,
            libc6: true,
            libc: true,
            debconf: true,
          },
        },
        {
          ...defaultPkgProps,
          Name: 'pac4',
          Version: '1:2.29.2-1+deb9u1',
          Source: 'pac4_ng',
        },
      ],
    },
  ];

  for (const example of examples) {
    await t.test(example.description, async t => {
      const execStub = sinon.stub(subProcess, 'execute');

      execStub.withArgs('docker', [
        'run', '--rm', sinon.match.any, 'cat', '/var/lib/dpkg/status',
      ]).resolves(example.dpkgManifestLines.join('\n'));

      execStub.withArgs('docker', [
        'run', '--rm', sinon.match.any, 'cat', '/var/lib/apt/extended_states',
      ]).resolves(example.extManifestLines.join('\n'));

      t.teardown(() => execStub.restore());

      const actual = await analyzer.analyze('ubuntu:10.04');

      t.same(actual, {
        Image: 'ubuntu:10.04',
        AnalyzeType: 'Apt',
        Analysis: example.expectedPackages,
      });
    });
  }
});
