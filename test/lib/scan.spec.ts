import { mergeEnvVarsIntoCredentials } from "../../lib/scan";

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
