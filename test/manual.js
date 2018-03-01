var plugin = require('../lib');

function main() {
  var targetFile = process.argv[2];

  plugin.inspect('.', targetFile).then(function (result) {
    console.log(JSON.stringify(result, null, 2));
  }).catch(function (error) {
    console.log('Error:', error.stack);
  });

};

main();
