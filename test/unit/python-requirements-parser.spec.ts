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
});
