#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import { test } from 'tap';
import { buildResponse } from '../../lib/response-builder';

test('buildResponse', async (t) => {
  await t.test('with dockerfile analysis', async (t) => {
    const runtime = 'docker 18.09.2';
    const depsAna = require('../fixtures/analysis-results/deps');
    const dockerfileAna = require('../fixtures/analysis-results/dockerfile');
    const expected = require('../fixtures/responses/all-deps');

    await t.test('returns a complete response', async (t) => {
      const response = buildResponse(runtime, depsAna, dockerfileAna, {});

      t.same(response, expected, 'response matches fixture');
    });

    await t.test('returns package dependencies', async (t) => {
      const response = buildResponse(runtime, depsAna, dockerfileAna, {});
      const deps = response.package.dependencies;

      t.ok(deps['wget'], 'include wget from dockerfile');
      t.ok(deps['openssl'], 'include openssl via wget from dockerfile');
      t.ok(deps['bash'], 'include bash from base image');
      t.ok(deps['grep'], 'include grep from base image');
    });
  });
});
