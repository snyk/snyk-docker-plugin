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

  it("does not append latest to docker archive path", () => {
    const ociArchivePath = "oci-archive:some/path/image.tar";
    expect(appendLatestTagIfMissing(ociArchivePath)).toEqual(ociArchivePath);
  });

  it("does not append latest if tag exists", () => {
    const imageWithTag = "image:sometag";
    expect(appendLatestTagIfMissing(imageWithTag)).toEqual(imageWithTag);
  });

  it("does not modify targetImage with sha", () => {
    const imageWithSha =
      "snyk container test nginx@sha256:56ea7092e72db3e9f84d58d583370d59b842de02ea9e1f836c3f3afc7ce408c1";
    expect(appendLatestTagIfMissing(imageWithSha)).toEqual(imageWithSha);
  });

  it("appends latest if no tag exists", () => {
    const imageWithoutTag = "image";
    expect(appendLatestTagIfMissing(imageWithoutTag)).toEqual(
      `${imageWithoutTag}:latest`,
    );
  });
});
