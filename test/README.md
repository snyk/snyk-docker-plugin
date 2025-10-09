# snyk-docker-plugin tests

## Running tests

To run system tests the following environment variables need to be set:

- `DOCKER_HUB_PRIVATE_IMAGE` : `snykgoof/dockerhub-goof:alpine`
- `DOCKER_HUB_USERNAME` : `snykgoof`
- `DOCKER_HUB_PASSWORD` : <see 1password>

This is an image that is hosted on Docker Hub but not available publicly.
Note that the variables above are used purely for system test and are unrelated to the `SNYK_REGISTRY_USERNAME
` / `SNYK_REGISTRY_PASSWORD` environment variables which need to be present at runtime and can be found in 1password.

If tests should fail because that config hasn't been done, some artifacts will be left over/my_custom/image/save/path
/auth/{someGuid}. This needs to be manually deleted before subsequent runs to avoid more failures.

Additionally, you should have Docker installed and the Docker daemon should be running. This is because some tests require pulling container images beforehand and also other tests check functionality like pulling directly from the Docker socket. Also double check that `Use containerd for pulling and storing images` is unchecked in Docker desktop settings as using `containerd` leads to issues with SHA's not matching in some tests.

## Writing tests

The preferred way to write new tests is with `jest`. Simply put the `spec.ts` suffix to your test.

The `test.ts` suffix is used only with the old-style `tap` tests and should not be used.
