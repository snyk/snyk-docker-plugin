var test = require('tap').test;
var path = require('path');

var plugin = require('../lib');
var subProcess = require('../lib/sub-process');

test('Test for non exists docker', function (t) {
  return plugin.inspect('.', 'non-exists:latest').catch((error) => {
    t.ok(error.message.includes('reference does not exist'));
  })
});