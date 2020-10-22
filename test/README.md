# snyk-docker-plugin tests

## Running tests

To run tests the following environment variables need to be set:

- `DOCKER_HUB_PRIVATE_IMAGE`
- `DOCKER_HUB_USERNAME`
- `DOCKER_HUB_PASSWORD`

`DOCKER_HUB_PRIVATE_IMAGE` should refer to an image that is hosted on Docker Hub but not available publicly. During CI test this is set to `snykgoof/dockergoof:alpine`.

Additionally, you should have Docker installed and the Docker daemon should be running. This is because some tests require pulling container images beforehand and also other tests check functionality like pulling directly from the Docker socket.

## Writing tests

The preferred way to write new tests is with `jest`. Simply put the `spec.ts` suffix to your test.

The `test.ts` suffix is used only with the old-style `tap` tests and should not be used.
