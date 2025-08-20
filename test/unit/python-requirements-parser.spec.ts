import { getRequirements } from "../../lib/python-parser/requirements-parser";

describe("python requirements parser", () => {
  it("correctly parses a requirements file", () => {
    const fileContent = `
      Jinja2==2.7.2
      oauth2>=1.1.3
      pyramid==1.3a6
    `;
    const requirements = getRequirements(fileContent);
    expect(requirements).toHaveLength(3);
    expect(requirements).toMatchObject([
      { name: "jinja2", specifier: "=", version: "2.7.2" },
      { name: "oauth2", specifier: ">=", version: "1.1.3" },
      { name: "pyramid", specifier: "=", version: "1.3a6" },
    ]);
  });

  it("parses package names without versions", () => {
    const fileContent = `
      jinja2==2.7.2
      oauth2
      pyramid~=1.3a6
    `;
    const requirements = getRequirements(fileContent);
    expect(requirements).toHaveLength(3);
    expect(requirements).toMatchObject([
      { name: "jinja2", specifier: "=", version: "2.7.2" },
      { name: "oauth2" },
      { name: "pyramid", specifier: "^", version: "1.3a6" },
    ]);
  });

  it("ignore commented lines", () => {
    const fileContent = `
      Jinja2==2.7.2
      # oauth2>=1.1.3
      #pyramid==1.3a6
    `;
    const requirements = getRequirements(fileContent);
    expect(requirements).toHaveLength(1);
    expect(requirements).toMatchObject([
      { name: "jinja2", specifier: "=", version: "2.7.2" },
    ]);
  });

  it("ignores invalid requirement lines", () => {
    const fileContent = `
      valid-package==1.0.0
      [invalid requirement format]
      another-valid==2.0.0
      !@#$%^&*()
    `;
    const requirements = getRequirements(fileContent);
    expect(requirements).toHaveLength(2);
    expect(requirements).toMatchObject([
      { name: "valid-package", specifier: "=", version: "1.0.0" },
      { name: "another-valid", specifier: "=", version: "2.0.0" },
    ]);
  });

  it("handles empty lines", () => {
    const fileContent = `
      package1==1.0.0
      
      
      package2==2.0.0
    `;
    const requirements = getRequirements(fileContent);
    expect(requirements).toHaveLength(2);
    expect(requirements).toMatchObject([
      { name: "package1", specifier: "=", version: "1.0.0" },
      { name: "package2", specifier: "=", version: "2.0.0" },
    ]);
  });
});
