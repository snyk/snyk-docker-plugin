const test = require('tap-only');
const nock = require('nock');
const fsExtra = require('fs-extra');
const pathUtil = require('path');

const plugin = require('../lib');
const subProcess = require('../lib/sub-process');

test('throws if cant fetch analyzer', function (t) {
  t.tearDown(() => {
    nock.restore();
  });

  const downloadServer = nock('https://snyk.io')
    .get(/\/resources\/.*/)
    .reply(400);

  fsExtra.removeSync(
    pathUtil.join(__dirname, '../bin/'));

  return plugin.inspect('debian:6')
    .catch((err) => {
      t.true(nock.isDone(), 'tried to download analyzer');
      t.is(err.statusCode, 400, 'expected statusCode');
      t.match(err.message, /bad.*http.*download/i, 'expected error message');
    });
});

test('fetches analyzer only if doesnt exist', function (t) {
  t.tearDown(() => {
    nock.restore();
  });

  const binFolder = pathUtil.join(__dirname, '../bin/');

  fsExtra.removeSync(binFolder);
  t.false(fsExtra.existsSync(binFolder), 'bin folder is deleted');

  return plugin.inspect('not-here:latest')
    .catch(() => {
      // TODO: check also file exists and not empty
      t.true(fsExtra.existsSync(binFolder), 'bin folder was created');

      if (!nock.isActive()) {
        nock.activate();
      }
      nock('https://snyk.io')
        .get(/\/resources\/.*/)
        .reply(400);

      return plugin.inspect('not-there:1.2.3')
    })
    .catch(() => {
      t.false(nock.isDone(), 'didnt try to download analyzer');
      nock.restore();
    })
});

test('inspect an image that doesnt exist', function (t) {
  return plugin.inspect('not-here:latest').catch((err) => {
    t.match(err.message, 'Docker image was not found:');
    t.pass('failed as expected');
  })
});

test('inspect nginx:1.13.10', function (t) {
  const imgName = 'nginx';
  const imgTag = '1.13.10';
  const img = imgName + ':' + imgTag;
  return dockerPull(t, img)
    .then(function () {
      return plugin.inspect(img);
    })
    .then(function (res) {
      const plugin = res.plugin;
      const pkg = res.package;

      t.equal(plugin.name, 'snyk-docker-plugin', 'plugin name');
      t.equal(plugin['project-name'], img, `project-name is ${img}`);

      t.match(pkg, {
        name: imgName,
        version: imgTag,
        packageFormatVersion: 'deb:0.0.1',
        dockerOSRelease: {
          name: 'debian',
          version: '9',
        },
      }, 'root pkg');

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 108, 'expected number of deps');
      t.match(deps, {
        'acl/libacl1': {
          name: 'acl/libacl1',
          version: '2.2.52-3+b1',
        },
        adduser: {
          name: 'adduser',
          version: '3.115',
        },
        'nginx-module-xslt': {
          name: 'nginx-module-xslt',
          version: '1.13.10-1~stretch',
        },
        'openssl/libssl1.1': {
          name: 'openssl/libssl1.1',
          version: '1.1.0f-3+deb9u1',
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
      return plugin.inspect(img);
    })
    .then(function (res) {
      const plugin = res.plugin;
      const pkg = res.package;

      t.equal(plugin.name, 'snyk-docker-plugin', 'plugin name');
      t.equal(plugin['project-name'], img, `project-name is ${img}`);

      t.match(pkg, {
        name: imgName,
        version: imgTag,
        packageFormatVersion: 'apk:0.0.1',
        dockerOSRelease: {
          name: 'alpine',
          version: '3.7.0',
        },
      }, 'root pkg');

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 13, 'expected number of deps');
      t.match(deps, {
        busybox: {
          name: 'busybox',
          version: '1.27.2-r7',
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
      return plugin.inspect(img);
    })
    .then(function (res) {
      const plugin = res.plugin;
      const pkg = res.package;

      t.equal(plugin.name, 'snyk-docker-plugin', 'plugin name');
      t.equal(plugin['project-name'], img, `project-name is ${img}`);

      t.match(pkg, {
        name: imgName,
        version: imgTag,
        packageFormatVersion: 'rpm:0.0.1',
        dockerOSRelease: {
          name: 'centos',
          version: '7',
        },
      }, 'root pkg');

      const deps = pkg.dependencies;

      t.equal(Object.keys(deps).length, 145, 'expected number of deps');
      t.match(deps, {
        'openssl-libs': {
          name: 'openssl-libs',
          version: '1:1.0.2k-8.el7',
        },
        passwd: {
          name: 'passwd',
          version: '0.79-4.el7',
        },
        systemd: {
          name: 'systemd',
          version: '219-42.el7',
        },
        dracut: {
          name: 'dracut',
          version: '033-502.el7', // TODO: make sure we handle this well
        },
        iputils: {
          version: '20160308-10.el7',
        },
      }, 'deps');
    });
});

function dockerPull(t, name) {
  t.comment('pulling ' + name);
  return subProcess.execute('docker', ['image', 'pull', name]);
}
