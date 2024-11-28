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

  it("parses extra names when present", () => {
    const fileContent = `
      Metadata-Version: 2.1
      Name: fastapi
      Version: 0.115.4
      Summary: FastAPI framework, high performance, easy to learn, fast to code, ready for production
      Author-Email: =?utf-8?q?Sebasti=C3=A1n_Ram=C3=ADrez?= <tiangolo@gmail.com>
      Classifier: Intended Audience :: Information Technology
      Classifier: Intended Audience :: System Administrators
      Classifier: Operating System :: OS Independent
      Classifier: Programming Language :: Python :: 3
      Classifier: Programming Language :: Python
      Classifier: Topic :: Internet
      Classifier: Topic :: Software Development :: Libraries :: Application Frameworks
      Classifier: Topic :: Software Development :: Libraries :: Python Modules
      Classifier: Topic :: Software Development :: Libraries
      Classifier: Topic :: Software Development
      Classifier: Typing :: Typed
      Classifier: Development Status :: 4 - Beta
      Classifier: Environment :: Web Environment
      Classifier: Framework :: AsyncIO
      Classifier: Framework :: FastAPI
      Classifier: Framework :: Pydantic
      Classifier: Framework :: Pydantic :: 1
      Classifier: Intended Audience :: Developers
      Classifier: License :: OSI Approved :: MIT License
      Classifier: Programming Language :: Python :: 3 :: Only
      Classifier: Programming Language :: Python :: 3.8
      Classifier: Programming Language :: Python :: 3.9
      Classifier: Programming Language :: Python :: 3.10
      Classifier: Programming Language :: Python :: 3.11
      Classifier: Programming Language :: Python :: 3.12
      Classifier: Topic :: Internet :: WWW/HTTP :: HTTP Servers
      Classifier: Topic :: Internet :: WWW/HTTP
      Project-URL: Homepage, https://github.com/fastapi/fastapi
      Project-URL: Documentation, https://fastapi.tiangolo.com/
      Project-URL: Repository, https://github.com/fastapi/fastapi
      Project-URL: Issues, https://github.com/fastapi/fastapi/issues
      Project-URL: Changelog, https://fastapi.tiangolo.com/release-notes/
      Requires-Python: >=3.8
      Requires-Dist: starlette<0.42.0,>=0.40.0
      Requires-Dist: pydantic!=1.8,!=1.8.1,!=2.0.0,!=2.0.1,!=2.1.0,<3.0.0,>=1.7.4
      Requires-Dist: typing-extensions>=4.8.0
      Provides-Extra: standard
      Requires-Dist: fastapi-cli[standard]>=0.0.5; extra == "standard"
      Requires-Dist: httpx>=0.23.0; extra == "standard"
      Requires-Dist: jinja2>=2.11.2; extra == "standard"
      Requires-Dist: python-multipart>=0.0.7; extra == "standard"
      Requires-Dist: email-validator>=2.0.0; extra == "standard"
      Requires-Dist: uvicorn[standard]>=0.12.0; extra == "standard"
      Provides-Extra: all
      Requires-Dist: fastapi-cli[standard]>=0.0.5; extra == "all"
      Requires-Dist: httpx>=0.23.0; extra == "all"
      Requires-Dist: jinja2>=2.11.2; extra == "all"
      Requires-Dist: python-multipart>=0.0.7; extra == "all"
      Requires-Dist: itsdangerous>=1.1.0; extra == "all"
      Requires-Dist: pyyaml>=5.3.1; extra == "all"
      Requires-Dist: ujson!=4.0.2,!=4.1.0,!=4.2.0,!=4.3.0,!=5.0.0,!=5.1.0,>=4.0.1; extra == "all"
      Requires-Dist: orjson>=3.2.1; extra == "all"
      Requires-Dist: email-validator>=2.0.0; extra == "all"
      Requires-Dist: uvicorn[standard]>=0.12.0; extra == "all"
      Requires-Dist: pydantic-settings>=2.0.0; extra == "all"
      Requires-Dist: pydantic-extra-types>=2.0.0; extra == "all"
      Description-Content-Type: text/markdown`;
    const packageResult = getPackageInfo(fileContent);
    expect(packageResult.dependencies).toEqual([
      {
        extras: [],
        extraEnvMarkers: [],
        name: "starlette",
        specifier: "<",
        version: "0.42.0",
      },
      {
        extras: [],
        extraEnvMarkers: [],
        name: "pydantic",
        specifier: "!=",
        version: "1.8",
      },
      {
        extras: [],
        extraEnvMarkers: [],
        name: "typing-extensions",
        specifier: ">=",
        version: "4.8.0",
      },
      {
        extras: ["standard"],
        extraEnvMarkers: ["standard"],
        name: "fastapi-cli",
        specifier: ">=",
        version: "0.0.5",
      },
      {
        extras: [],
        extraEnvMarkers: ["standard"],
        name: "httpx",
        specifier: ">=",
        version: "0.23.0",
      },
      {
        extras: [],
        extraEnvMarkers: ["standard"],
        name: "jinja2",
        specifier: ">=",
        version: "2.11.2",
      },
      {
        extras: [],
        extraEnvMarkers: ["standard"],
        name: "python-multipart",
        specifier: ">=",
        version: "0.0.7",
      },
      {
        extras: [],
        extraEnvMarkers: ["standard"],
        name: "email-validator",
        specifier: ">=",
        version: "2.0.0",
      },
      {
        extras: ["standard"],
        extraEnvMarkers: ["standard"],
        name: "uvicorn",
        specifier: ">=",
        version: "0.12.0",
      },
      {
        extras: ["standard"],
        extraEnvMarkers: ["all"],
        name: "fastapi-cli",
        specifier: ">=",
        version: "0.0.5",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "httpx",
        specifier: ">=",
        version: "0.23.0",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "jinja2",
        specifier: ">=",
        version: "2.11.2",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "python-multipart",
        specifier: ">=",
        version: "0.0.7",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "itsdangerous",
        specifier: ">=",
        version: "1.1.0",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "pyyaml",
        specifier: ">=",
        version: "5.3.1",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "ujson",
        specifier: "!=",
        version: "4.0.2",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "orjson",
        specifier: ">=",
        version: "3.2.1",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "email-validator",
        specifier: ">=",
        version: "2.0.0",
      },
      {
        extras: ["standard"],
        extraEnvMarkers: ["all"],
        name: "uvicorn",
        specifier: ">=",
        version: "0.12.0",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "pydantic-settings",
        specifier: ">=",
        version: "2.0.0",
      },
      {
        extras: [],
        extraEnvMarkers: ["all"],
        name: "pydantic-extra-types",
        specifier: ">=",
        version: "2.0.0",
      },
    ]);
  });
});
