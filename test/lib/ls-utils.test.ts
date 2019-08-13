#!/usr/bin/env node_modules/.bin/ts-node
// Shebang is required, and file *has* to be executable: chmod +x file.test.js
// See: https://github.com/tapjs/node-tap/issues/313#issuecomment-250067741

import * as path from "path";
import { test } from "tap";
import { iterateFiles, parseLsOutput } from "../../lib/ls-utils";

const PARSER_TESTS = [
  {
    name: "Empty string",
    in: "",
    out: {
      name: "/",
      subDirs: [],
      files: [],
    },
    files: [],
  },
  {
    name: "Empty directory",
    in: ".\n..\n",
    out: {
      name: "/",
      subDirs: [],
      files: [],
    },
    files: [],
  },
  {
    name: "Empty directory recursive output",
    in: "/app/dir2:\n./\n../\n",
    out: {
      name: "/",
      subDirs: [],
      files: [],
    },
    files: [],
  },
  {
    name: "Single directory with dirs and files",
    in: "./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\nfile2.txt\n",
    out: {
      name: "/",
      subDirs: [],
      files: [
        {
          name: "file1.txt",
          path: "/",
        },
        {
          name: "file2.txt",
          path: "/",
        },
      ],
    },
    files: ["/file1.txt", "/file2.txt"],
  },
  {
    name: "Single directory with a file recursive version",
    in: "/app/dir3:\n./\n../\nfile6.json\n",
    out: {
      name: "/",
      subDirs: [],
      files: [
        {
          name: "file6.json",
          path: "/",
        },
      ],
    },
    files: ["/file6.json"],
  },
  {
    name: "Directory structure with dirs and files of the /app subdirectory",
    in:
      "/app:\n./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\nfile2.txt\n\n/app/dir1:" +
      "\n./\n../\ndir11/\nfile3.json\nfile4.txt\n\n/app/dir1/dir11:\n./\n../\n" +
      "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.json\n",
    out: {
      name: "/",
      subDirs: [
        {
          files: [
            {
              name: "file3.json",
              path: "/dir1",
            },
            {
              name: "file4.txt",
              path: "/dir1",
            },
          ],
          name: "dir1",
          subDirs: [
            {
              files: [
                {
                  name: "file5.txt",
                  path: "/dir1/dir11",
                },
              ],
              name: "dir11",
              subDirs: [],
            },
          ],
        },
        {
          files: [],
          name: "dir2",
          subDirs: [],
        },
        {
          files: [
            {
              name: "file6.json",
              path: "/dir3",
            },
          ],
          name: "dir3",
          subDirs: [],
        },
      ],
      files: [
        {
          name: "file1.txt",
          path: "/",
        },
        {
          name: "file2.txt",
          path: "/",
        },
      ],
    },
    files: [
      "/file1.txt",
      "/file2.txt",
      "/dir1/file3.json",
      "/dir1/file4.txt",
      "/dir1/dir11/file5.txt",
      "/dir3/file6.json",
    ],
  },
  {
    name: "Directory structure with missing parents",
    in:
      "/app:\n./\n../\ndir1/\ndir2/\ndir3/\nfile1.txt\nfile2.txt\n\n/app/dir1/dir11:\n./\n../\n" +
      "file5.txt\n\n/app/dir2:\n./\n../\n\n/app/dir3:\n./\n../\nfile6.json\n",
    out: {
      name: "/",
      subDirs: [
        {
          files: [],
          name: "dir1",
          subDirs: [
            {
              files: [
                {
                  name: "file5.txt",
                  path: "/dir1/dir11",
                },
              ],
              name: "dir11",
              subDirs: [],
            },
          ],
        },
        {
          files: [],
          name: "dir2",
          subDirs: [],
        },
        {
          files: [
            {
              name: "file6.json",
              path: "/dir3",
            },
          ],
          name: "dir3",
          subDirs: [],
        },
      ],
      files: [
        {
          name: "file1.txt",
          path: "/",
        },
        {
          name: "file2.txt",
          path: "/",
        },
      ],
    },
    files: [
      "/file1.txt",
      "/file2.txt",
      "/dir1/dir11/file5.txt",
      "/dir3/file6.json",
    ],
  },
];

test("parse ls output", async (t) => {
  PARSER_TESTS.forEach((data) => {
    t.test(data.name, async (t) => {
      const res = parseLsOutput(data.in);
      const files: string[] = [];
      iterateFiles(res, (f) => files.push(path.join(f.path, f.name)));
      t.same(res, data.out);
      t.same(files, data.files);
    });
  });
});
