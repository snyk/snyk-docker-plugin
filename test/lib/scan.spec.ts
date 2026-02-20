import {
  appendLatestTagIfMissing,
  mergeEnvVarsIntoCredentials,
} from "../../lib/scan";

describe("mergeEnvVarsIntoCredentials", () => {
  const oldEnvVars = { ...process.env };
  const FLAG_USER = "flagUser";
  const ENV_VAR_USER = "envVarUser";
  const FLAG_PASSWORD = "flagPassword";
  const ENV_VAR_PASSWORD = "envVarPassword";

  beforeEach(() => {
    delete process.env.SNYK_REGISTRY_USERNAME;
    delete process.env.SNYK_REGISTRY_PASSWORD;
  });

  afterEach(() => {
    process.env = { ...oldEnvVars };
  });

  // prettier-ignore
  it.each`
    
    usernameFlag | usernameEnvVar  |  expectedUsername 
    
    ${undefined} | ${undefined}    |  ${undefined}
    ${FLAG_USER} | ${undefined}    |  ${FLAG_USER}   
    ${undefined} | ${ENV_VAR_USER} |  ${ENV_VAR_USER}
    ${FLAG_USER} | ${ENV_VAR_USER} |  ${FLAG_USER}
        
  `("should set username to $expectedUsername when flag is $usernameFlag and envvar is $usernameEnvVar",
    ({
      usernameFlag,
      usernameEnvVar,
      expectedUsername,
    }) => {
      if (usernameEnvVar) {
        process.env.SNYK_REGISTRY_USERNAME = usernameEnvVar;
      }
      const options = {
        username: usernameFlag,
      };

      mergeEnvVarsIntoCredentials(options);

      expect(options.username).toEqual(expectedUsername);
    });

  // prettier-ignore
  it.each`
    
    passwordFlag     | passwordEnvVar      |  expectedPassword 
    
    ${undefined}     | ${undefined}        | ${undefined}
    ${FLAG_PASSWORD} | ${undefined}        | ${FLAG_PASSWORD}   
    ${undefined}     | ${ENV_VAR_PASSWORD} | ${ENV_VAR_PASSWORD}
    ${FLAG_PASSWORD} | ${ENV_VAR_PASSWORD} | ${FLAG_PASSWORD}
        
  `("should set password to $expectedPassword when flag is $passwordFlag and envvar is $passwordEnvVar",
    ({
      passwordFlag,
      passwordEnvVar,
      expectedPassword,
    }) => {
      if (passwordEnvVar) {
        process.env.SNYK_REGISTRY_PASSWORD = passwordEnvVar;
      }
      const options = {
        password: passwordFlag,
      };

      mergeEnvVarsIntoCredentials(options);

      expect(options.password).toEqual(expectedPassword);
    });
});

describe("appendLatestTagIfMissing", () => {
  it("does not append latest to docker archive path", () => {
    const dockerArchivePath = "docker-archive:some/path/image.tar";
    expect(appendLatestTagIfMissing(dockerArchivePath)).toEqual(
      dockerArchivePath,
    );
  });

  it("does not append latest to oci archive path", () => {
    const ociArchivePath = "oci-archive:some/path/image.tar";
    expect(appendLatestTagIfMissing(ociArchivePath)).toEqual(ociArchivePath);
  });

  it("does not append latest to kaniko-archive path", () => {
    const path = "kaniko-archive:some/path/image.tar";
    expect(appendLatestTagIfMissing(path)).toEqual(path);
  });

  it("does not append latest to unspecified archive path (.tar)", () => {
    const path = "/tmp/nginx.tar";
    expect(appendLatestTagIfMissing(path)).toEqual(path);
  });

  it("does not append latest if tag exists", () => {
    const imageWithTag = "image:sometag";
    expect(appendLatestTagIfMissing(imageWithTag)).toEqual(imageWithTag);
  });

  it("does not append latest if digest exists (digest-only reference)", () => {
    const imageWithDigest =
      "nginx@sha256:56ea7092e72db3e9f84d58d583370d59b842de02ea9e1f836c3f3afc7ce408c1";
    expect(appendLatestTagIfMissing(imageWithDigest)).toEqual(
      imageWithDigest,
    );
  });

  it("does not append latest if both tag and digest exist", () => {
    const imageWithTagAndDigest =
      "nginx:1.23@sha256:56ea7092e72db3e9f84d58d583370d59b842de02ea9e1f836c3f3afc7ce408c1";
    expect(appendLatestTagIfMissing(imageWithTagAndDigest)).toEqual(
      imageWithTagAndDigest,
    );
  });

  it("appends latest for repository-only reference", () => {
    expect(appendLatestTagIfMissing("image")).toEqual("image:latest");
  });

  it("appends latest for repository with namespace", () => {
    expect(appendLatestTagIfMissing("library/nginx")).toEqual(
      "library/nginx:latest",
    );
  });

  it("appends latest for registry with port and no tag", () => {
    expect(appendLatestTagIfMissing("localhost:5000/foo/bar")).toEqual(
      "localhost:5000/foo/bar:latest",
    );
  });

  it("appends latest for custom registry without tag", () => {
    expect(appendLatestTagIfMissing("gcr.io/project/nginx")).toEqual(
      "gcr.io/project/nginx:latest",
    );
  });

  it("returns unchanged for invalid image reference", () => {
    const invalid = "/test:unknown";
    expect(appendLatestTagIfMissing(invalid)).toEqual(invalid);
  });
});