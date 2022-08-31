declare global {
  namespace jest {
    interface Matchers<R> {
      toBeDockerPackageInstallCommand(pkgName: string): R;
    }
  }
}

export function toBeDockerPackageInstallCommand(received, pkgName) {
  const installCmdRegex =
    /^(rpm\s+-i|rpm\s+--install|apk\s+((--update|-u|--no-cache)\s+)*add(\s+(--update|-u|--no-cache))*|apt-get\s+((--assume-yes|--yes|-y)\s+)*install(\s+(--assume-yes|--yes|-y))*|apt\s+((--assume-yes|--yes|-y)\s+)*install|yum\s+install|aptitude\s+install)\s+/;
  const pass =
    (installCmdRegex.test(received) &&
      received.indexOf(pkgName) > -1 &&
      !RegExp("/ {2,}|\t|\n/", "g").test(received) &&
      !RegExp("/^RUN( /bin/sh)?( -c)?/").test(received)) ||
    false;
  const message = pass
    ? () => `expected ${received} not to be a package installCommand`
    : () => `expected ${received} to be a package installCommand`;

  return {
    message,
    pass,
  };
}
