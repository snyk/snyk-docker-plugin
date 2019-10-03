#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import * as sinon from "sinon";
import { test } from "tap";

import * as analyzer from "../../../lib/analyzer/package-managers/rpm";
import * as rpmInput from "../../../lib/inputs/rpm/docker";
import * as subProcess from "../../../lib/sub-process";

test("analyze", async (t) => {
  const defaultPkgProps = {
    Name: null,
    Version: null,
    Source: null,
    Provides: [],
    Deps: {},
    AutoInstalled: null,
  };

  const examples = [
    {
      description: "No Rpm output",
      rpmOutputLines: [""],
      expectedPackages: [],
    },
    {
      description: "Single Package",
      rpmOutputLines: ["libcom_err\t1.41.12-23.el6\t59233"],
      expectedPackages: [
        { ...defaultPkgProps, Name: "libcom_err", Version: "1.41.12-23.el6" },
      ],
    },
    {
      description: "Multiple Packages",
      rpmOutputLines: [
        "basesystem\t10.0-4.el6\t0",
        "tzdata\t2018d-1.el6\t1960357",
        "glibc-common\t2.12-1.209.el6_9.2\t112436045",
        "glibc\t2.12-1.209.el6_9.2\t13121423",
      ],
      expectedPackages: [
        { ...defaultPkgProps, Name: "basesystem", Version: "10.0-4.el6" },
        { ...defaultPkgProps, Name: "tzdata", Version: "2018d-1.el6" },
        {
          ...defaultPkgProps,
          Name: "glibc-common",
          Version: "2.12-1.209.el6_9.2",
        },
        { ...defaultPkgProps, Name: "glibc", Version: "2.12-1.209.el6_9.2" },
      ],
    },
  ];

  for (const example of examples) {
    await t.test(example.description, async (t) => {
      const execStub = sinon.stub(subProcess, "execute");

      execStub
        .withArgs("docker", [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          sinon.match.any,
          "rpm",
          "--nodigest",
          "--nosignature",
          "-qa",
          "--qf",
          '"%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SIZE}\n"',
        ])
        .resolves({ stdout: example.rpmOutputLines.join("\n"), stderr: "" });

      t.teardown(() => execStub.restore());

      const rpmDbFileContent = await rpmInput.getRpmDbFileContent("centos:6");
      const actual = await analyzer.analyze("centos:6", rpmDbFileContent);

      t.same(actual, {
        Image: "centos:6",
        AnalyzeType: "Rpm",
        Analysis: example.expectedPackages,
      });
    });
  }
});

test("no rpm", async (t) => {
  const examples = [
    {
      targetImage: "alpine:2.6",
      rpmThrows:
        'docker: Error response from daemon: OCI runtime create failed: container_linux.go:348: starting container process caused "exec: "rpm": executable file not found in $PATH": unknown.',
    },
    {
      targetImage: "ubuntu:10.04",
      rpmThrows: "./docker-entrypoint.sh: line 9: exec: rpm: not found",
    },
  ];

  for (const example of examples) {
    await t.test(example.targetImage, async (t) => {
      const execStub = sinon.stub(subProcess, "execute");

      execStub
        .withArgs("docker", [
          "run",
          "--rm",
          "--entrypoint",
          '""',
          "--network",
          "none",
          sinon.match.any,
          "rpm",
          "--nodigest",
          "--nosignature",
          "-qa",
          "--qf",
          '"%{NAME}\t%|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\t%{SIZE}\n"',
        ])
        .callsFake(async (docker, [run, rm, image]) => {
          throw { stderr: example.rpmThrows, stdout: "" };
        });

      t.teardown(() => execStub.restore());

      const rpmDbFileContent = await rpmInput.getRpmDbFileContent(
        example.targetImage,
      );
      const actual = await analyzer.analyze(
        example.targetImage,
        rpmDbFileContent,
      );

      t.same(actual, {
        Image: example.targetImage,
        AnalyzeType: "Rpm",
        Analysis: [],
      });
    });
  }
});
