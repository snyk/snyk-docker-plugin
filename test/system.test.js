var test = require('tap-only');

var plugin = require('../lib');
var subProcess = require('../lib/sub-process');

test('Test for non exists docker', function (t) {
  return plugin.inspect('.', 'non-exists:latest').catch((error) => {
    t.pass('failed as expected');
  })
});

test('inspect nginx:1.13.10', function (t) {
  const imgName = 'nginx';
  const imgTag = '1.13.10';
  const img = imgName + ':' + imgTag;
  return dockerPull(t, img)
    .then(function () {
      return plugin.inspect('.', img);
    })
    .then(function (res) {
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
          ],
        },
        adduser: {
          name: 'adduser',
          version: '3.115',
          from: [
            'nginx@1.13.10',
            'adduser@3.115',
          ],
        },
        'nginx-module-xslt': {
          name: 'nginx-module-xslt',
          version: '1.13.10-1~stretch',
          from: [
            'nginx@1.13.10',
            'nginx-module-xslt@1.13.10-1~stretch',
          ],
        },
        openssl: {
          name: 'openssl',
          version: '1.1.0f-3+deb9u1',
          from: [
            'nginx@1.13.10',
            'openssl@1.1.0f-3+deb9u1',
          ],
        },
      }, 'deps');
    });
});

test('inspect redis:3.2.11-alpine', function (t) {
  const imgName = 'redis';
  const imgTag = '3.2.11-alpine';
  const img = imgName + ':' + imgTag;
  return dockerPull(t, img)
    .then(function () {
      return plugin.inspect('.', img);
    })
    .then(function (res) {
      const plugin = res.plugin;
      const pkg = res.package;

      t.equal(plugin.name, 'snyk-docker-plugin', 'name');
      t.equal(plugin.targetFile, img, 'targetFile');

      t.match(pkg, {
        name: imgName,
        version: imgTag,
        packageFormatVersion: 'apk:0.0.1',
        from: [imgName + '@' + imgTag],
      }, 'root pkg');

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 13, 'expected number of deps');
      t.match(deps, {
        busybox: {
          name: 'busybox',
          version: '1.27.2-r7',
          from: [
            imgName + '@' + imgTag,
            'busybox@1.27.2-r7',
          ],
        },
        'libressl2.6-libcrypto': {
          name: 'libressl2.6-libcrypto',
          version: '2.6.3-r0',
        },
        zlib: {
          name: 'zlib',
          version: '1.2.11-r1',
        },
      }, 'deps');
    });
});

test('inspect centos', function (t) {
  const imgName = 'centos';
  const imgTag = '7.4.1708';
  const img = imgName + ':' + imgTag;
  return dockerPull(t, img)
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
        packageFormatVersion: 'rpm:0.0.1',
        from: [imgName + '@' + imgTag],
      }, 'root pkg');

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 145, 'expected number of deps');
      t.match(deps, {
        'openssl-libs': {
          name: 'openssl-libs',
          version: '1.0.2k',
          from: [
            imgName + '@' + imgTag,
            'openssl-libs@1.0.2k',
          ],
        },
        passwd: {
          name: 'passwd',
          version: '0.79',
        },
        systemd: {
          name: 'systemd',
          version: '219',
        },
        dracut: {
          name: 'dracut',
          version: '033', // TODO: what is this weird version
        },
        iputils: {
          version: '20160308',
        },
      }, 'deps');
    });
});

function dockerPull(t, name) {
  t.comment('pulling ' + name);
  return subProcess.execute('docker', ['image', 'pull', name]);
}
