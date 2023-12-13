import { getPackageInfo } from "../../lib/python-parser/metadata-parser";
describe("python metadata parser", () => {
  it("parses package metadata", () => {
    const fileContent = `
      Metadata-Version: 2.1
      Name: click
      Version: 8.1.3
      Summary: Composable command line interface toolkit
      Home-page: https://palletsprojects.com/p/click/
      License: BSD-3-Clause
      Platform: UNKNOWN
      Classifier: Development Status :: 5 - Production/Stable
      Classifier: Intended Audience :: Developers
      Classifier: License :: OSI Approved :: BSD License
      Classifier: Operating System :: OS Independent
      Classifier: Programming Language :: Python
      Requires-Python: >=3.7
      Description-Content-Type: text/x-rst
      License-File: LICENSE.rst
      Requires-Dist: colorama ; platform_system == "Windows"
      Requires-Dist: importlib-metadata ; python_version < "3.8"
    `;
    const packageResult = getPackageInfo(fileContent);
    expect(packageResult.name).toEqual("click");
    expect(packageResult.version).toEqual("8.1.3");
    expect(packageResult.dependencies).toHaveLength(2);
  });

  it("parses package metadata with dependency versions", () => {
    const fileContent = `
    Metadata-Version: 2.1
    Name: Flask
    Version: 2.2.1
    Summary: A simple framework for building complex web applications.
    Home-page: https://palletsprojects.com/p/flask
    Classifier: Development Status :: 5 - Production/Stable
    Classifier: Environment :: Web Environment
    Classifier: Framework :: Flask
    Classifier: Intended Audience :: Developers
    Classifier: License :: OSI Approved :: BSD License
    Classifier: Operating System :: OS Independent
    Classifier: Programming Language :: Python
    Classifier: Topic :: Internet :: WWW/HTTP :: Dynamic Content
    Classifier: Topic :: Internet :: WWW/HTTP :: WSGI
    Classifier: Topic :: Internet :: WWW/HTTP :: WSGI :: Application
    Classifier: Topic :: Software Development :: Libraries :: Application Frameworks
    Requires-Python: >=3.7
    Description-Content-Type: text/x-rst
    License-File: LICENSE.rst
    Requires-Dist: Werkzeug (>=2.2.0)
    Requires-Dist: Jinja2 (>=3.0)
    Requires-Dist: itsdangerous (>=2.0)
    Requires-Dist: click (>=8.0)
    Requires-Dist: importlib-metadata (>=3.6.0) ; python_version < "3.10"
    Provides-Extra: async
    Requires-Dist: asgiref (>=3.2) ; extra == 'async'
    Provides-Extra: dotenv
    Requires-Dist: python-dotenv ; extra == 'dotenv'
    `;
    const packageResult = getPackageInfo(fileContent);
    expect(packageResult.name).toEqual("flask");
    expect(packageResult.version).toEqual("2.2.1");
    expect(packageResult.dependencies).toHaveLength(7);
    expect(packageResult.dependencies).toMatchObject([
      { name: "werkzeug", version: "2.2.0", specifier: ">=" },
      { name: "jinja2", version: "3.0", specifier: ">=" },
      { name: "itsdangerous", version: "2.0", specifier: ">=" },
      { name: "click", version: "8.0", specifier: ">=" },
      { name: "importlib-metadata", version: "3.6.0", specifier: ">=" },
      { name: "asgiref", version: "3.2", specifier: ">=" },
      { name: "python-dotenv" },
    ]);
  });

  it("parses package metadata with non-semver version", () => {
    const fileContent = `
      Metadata-Version: 2.1
      Name: click
      Version: 8.3.post11545
      Summary: Composable command line interface toolkit
      Home-page: https://palletsprojects.com/p/click/
      License: BSD-3-Clause
      Platform: UNKNOWN
      Classifier: Development Status :: 5 - Production/Stable
      Classifier: Intended Audience :: Developers
      Classifier: License :: OSI Approved :: BSD License
      Classifier: Operating System :: OS Independent
      Classifier: Programming Language :: Python
      Requires-Python: >=3.7
      Description-Content-Type: text/x-rst
      License-File: LICENSE.rst
      Requires-Dist: colorama ; platform_system == "Windows"
      Requires-Dist: importlib-metadata ; python_version < "3.8"
    `;
    const packageResult = getPackageInfo(fileContent);
    expect(packageResult.name).toEqual("click");
    expect(packageResult.version).toEqual("8.3.0");
    expect(packageResult.dependencies).toHaveLength(2);
  });

  it("fails to parse package metadata when version can't be coerced to semver", () => {
    const fileContent = `
      Metadata-Version: 2.1
      Name: click
      Version: dfsd.fsdfs.df
      Summary: Composable command line interface toolkit
      Home-page: https://palletsprojects.com/p/click/
      License: BSD-3-Clause
      Platform: UNKNOWN
      Classifier: Development Status :: 5 - Production/Stable
      Classifier: Intended Audience :: Developers
      Classifier: License :: OSI Approved :: BSD License
      Classifier: Operating System :: OS Independent
      Classifier: Programming Language :: Python
      Requires-Python: >=3.7
      Description-Content-Type: text/x-rst
      License-File: LICENSE.rst
      Requires-Dist: colorama ; platform_system == "Windows"
      Requires-Dist: importlib-metadata ; python_version < "3.8"
    `;
    expect(() => {
      getPackageInfo(fileContent);
    }).toThrow();
  });

  it("Parses a package metadata when version isn't valid semver but has additional sections", () => {
    const fileContent = `
      Metadata-Version: 2.1
      Name: opencv-python
      Version: 4.8.1.78
      Summary: Wrapper package for OpenCV python bindings.
      Home-page: https://github.com/opencv/opencv-python
      Maintainer: OpenCV Team
      License: Apache 2.0
      Platform: UNKNOWN
      Requires-Python: >=3.6
      Description-Content-Type: text/markdown
      License-File: LICENSE-3RD-PARTY.txt
      License-File: LICENSE.txt
      Requires-Dist: numpy (>=1.13.3) ; python_version < "3.7"
      Requires-Dist: numpy (>=1.21.0) ; python_version <= "3.9" and platform_system == "Darwin" and platform_machine == "arm64"
      Requires-Dist: numpy (>=1.21.2) ; python_version >= "3.10"
      Requires-Dist: numpy (>=1.21.4) ; python_version >= "3.10" and platform_system == "Darwin"
      Requires-Dist: numpy (>=1.23.5) ; python_version >= "3.11"
      Requires-Dist: numpy (>=1.19.3) ; python_version >= "3.6" and platform_system == "Linux" and platform_machine == "aarch64"
      Requires-Dist: numpy (>=1.17.0) ; python_version >= "3.7"
      Requires-Dist: numpy (>=1.17.3) ; python_version >= "3.8"
      Requires-Dist: numpy (>=1.19.3) ; python_version >= "3.9"
    `;
    const packageResult = getPackageInfo(fileContent);
    expect(packageResult.name).toEqual("opencv-python");
    expect(packageResult.version).toEqual("4.8.1.78");
  });
});
