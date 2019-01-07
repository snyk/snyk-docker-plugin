#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import { test } from 'tap';

import * as analyzer from '../../../lib/analyzer/rpm-analyzer';
import { AnalyzerPkg } from '../../../lib/analyzer/types';

test('analyze', async t => {
  const defaultPkgProps = {
    Name: null,
    Version: null,
    Source: null,
    Provides: [],
    Deps: {},
    AutoInstalled: null,
  };

  const expectedPkgs = [
    {
      ...defaultPkgProps,
      Name: 'info',
      Version: '4.13a-8.el6',
      Deps: {
        'glibc': true,
        'zlib': true,
        'ncurses-libs': true,
        'bash': true
      }
    },
    {
      ...defaultPkgProps,
      Name: 'basesystem',
      Version: '10.0-4.el6',
      Deps: {
        'filesystem': true,
        'setup': true
      },
    },
  ];

  const actual = await analyzer.analyze('centos:6');
  const actualPkgMap = actual.Analysis.reduce(
    (map, pkg) => {
      map[pkg.Name] = pkg;
      return map;
    },
    {}
  );

  for (const expectedPkg of expectedPkgs) {
    const actualPkg = actualPkgMap[expectedPkg.Name]
    t.same(actualPkg, expectedPkg)
  }
});

test('no rpm', async t => {
  const targetImages = ['alpine:2.6', 'ubuntu:10.04']

  for (const targetImage of targetImages) {
    await t.test(targetImage, async t => {
      const actual = await analyzer.analyze(targetImage);

      t.same(actual, {
        Image: targetImage,
        AnalyzeType: 'Rpm',
        Analysis: [],
      });
    });
  }
});
