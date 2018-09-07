#!/usr/bin/env node

var plugin = require('../dist');
var analyzer = require('../dist/analyzer');

function analyze(targetImage) {
  return analyzer.analyze(targetImage);
}


function main() {
  var targetImage = process.argv[2];
  var analyzeOnly = process.argv.indexOf('--analyze') > 0;
  var cmd = analyzeOnly ? analyze : plugin.inspect;

  cmd(targetImage).then(function (result) {
    console.log(JSON.stringify(result, null, 2));
  }).catch(function (error) {
    console.log('Error:', error.stack);
  });

};

main();
