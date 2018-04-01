var test = require('tap-only');

var plugin = require('../lib');
var subProcess = require('../lib/sub-process');

test('Test for non exists docker', function (t) {
  return plugin.inspect('.', 'non-exists:latest').catch((error) => {
    t.pass('failed as expected');
  })
});

test('inspect nginx:1.13.19', function (t) {
  const imgName = 'nginx';
  const imgTag = '1.13.10';
  const img = imgName + ':' + imgTag;
  return dockerPull(img)
    .then(function () {
      return plugin.inspect('.', img);
    })
    .then(function (res) {
      console.log('KOKO', JSON.stringify(res, 0, 2));

      const plugin = res.plugin;
      const pkg = res.package;

      t.equal(plugin.name, 'snyk-docker-plugin', 'name');
      t.equal(plugin.targetFile, img, 'targetFile');

      t.match(pkg, {
        name: imgName,
        version: imgTag,
        packageFormatVersion: 'deb:0.0.1',
        from: [imgName + '@' + imgTag],
      }, 'root pkg');

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 80, 'expected number of deps');
      t.match(deps, {
        acl: {
          name: 'acl',
          version: '2.2.52-3+b1',
          from: [
            'nginx@1.13.10',
            'acl@2.2.52-3+b1',
          ]
        },
        adduser: {
          name: 'adduser',
          version: '3.115',
          from: [
            'nginx@1.13.10',
            'adduser@3.115',
          ]
        },
        'nginx-module-xslt': {
          name: 'nginx-module-xslt',
          version: '1.13.10-1~stretch',
          from: [
            'nginx@1.13.10',
            'nginx-module-xslt@1.13.10-1~stretch'
          ]
        },
        openssl: {
          name: 'openssl',
          version: '1.1.0f-3+deb9u1',
          from: [
            'nginx@1.13.10',
            'openssl@1.1.0f-3+deb9u1',
          ]
        },
      }, 'deps');
    });

});

function dockerPull(name) {
  return subProcess.execute('docker', ['image', 'pull', name]);
}
