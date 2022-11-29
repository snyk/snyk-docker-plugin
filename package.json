{
  "name": "snyk-docker-plugin",
  "description": "Snyk CLI docker plugin",
  "author": "snyk.io",
  "license": "Apache-2.0",
  "homepage": "https://github.com/snyk/snyk-docker-plugin",
  "repository": {
    "type": "git",
    "url": "https://github.com/snyk/snyk-docker-plugin"
  },
  "main": "dist/index.js",
  "types": "dist/index.d.js",
  "scripts": {
    "build": "tsc",
    "build-watch": "tsc -w",
    "debug": "tsc-watch --project tsconfig.json --onSuccess 'node --inspect --inspect-brk .'",
    "lint": "run-p --max-parallel=${JOBS:-5} --aggregate-output lint:*",
    "lint:prettier": "prettier --check \"{lib,test}/**/*.ts\"",
    "lint:tslint": "tslint --format stylish \"{lib,test}/**/*.ts\"",
    "lint:commit": "commitlint --from=HEAD~5",
    "format": "prettier --loglevel warn --write '{lib,test}/**/*.ts' && tslint --fix --format stylish '{lib,test}/**/*.ts'",
    "test": "npm run unit-test && npm run test-jest",
    "test-jest": "jest --ci --maxWorkers=3 --logHeapUsage",
    "test-windows": "tap test/windows/**/*.test.ts -R=spec --timeout=300",
    "test-jest-windows": "jest --ci --maxWorkers=3 --config test/windows/jest.config.js --logHeapUsage",
    "unit-test": "tap test/**/*.test.ts -R=spec --timeout=300",
    "prepare": "npm run build"
  },
  "engines": {
    "node": ">=12"
  },
  "dependencies": {
    "@snyk/composer-lockfile-parser": "^1.4.1",
    "@snyk/dep-graph": "^2.3.0",
    "@snyk/rpm-parser": "^2.3.2",
    "@snyk/snyk-docker-pull": "^3.7.4",
    "adm-zip": "^0.5.5",
    "chalk": "^2.4.2",
    "debug": "^4.1.1",
    "docker-modem": "3.0.3",
    "dockerfile-ast": "0.2.1",
    "elfy": "^1.0.0",
    "event-loop-spinner": "^2.0.0",
    "gunzip-maybe": "^1.4.2",
    "mkdirp": "^1.0.4",
    "semver": "^7.3.4",
    "shescape": "1.6.1",
    "snyk-nodejs-lockfile-parser": "1.40.0",
    "snyk-poetry-lockfile-parser": "^1.1.7",
    "tar-stream": "^2.1.0",
    "tmp": "^0.2.1",
    "tslib": "^1",
    "uuid": "^8.2.0",
    "varint": "^6.0.0"
  },
  "devDependencies": {
    "@commitlint/cli": "^17.0.2",
    "@commitlint/config-conventional": "^17.0.2",
    "@types/adm-zip": "^0.4.34",
    "@types/debug": "^4.1.5",
    "@types/jest": "^27.0.2",
    "@types/node": "14.14.31",
    "@types/sinon": "5.0.5",
    "@types/tar-stream": "^1.6.1",
    "@types/tmp": "^0.2.0",
    "jest": "^26.4.2",
    "npm-run-all": "^4.1.5",
    "prettier": "^2.7.1",
    "sinon": "^6",
    "tap": "^14.10.8",
    "ts-jest": "^26.4.0",
    "ts-node": "^10.2.1",
    "tsc-watch": "^4.2.8",
    "tslint": "^5.16.0",
    "tslint-config-prettier": "^1.18.0",
    "typescript": "~4.7.3"
  },
  "release": {
    "branches": [
      "main"
    ]
  }
}
