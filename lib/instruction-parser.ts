export { getPackagesFromRunInstructions, DockerFilePackages };

interface DockerFilePackages {
  [packageName: string]: {
    instruction: string;
  };
}

// tslint:disable-next-line:max-line-length
const installRegex = /\s*(rpm\s+-i|rpm\s+--install|apk\s+add|apt\s+install|apt-get\s+install|yum\s+install|aptitude\s+install)\s+/;

/*
 * This is fairly ugly because a single RUN could contain multiple install
 * commands, which in turn may install multiple packages, so we've got a
 * 3-level nested array (RUN instruction[] -> install[] -> package[])
 *
 * We also need to account for the multiple ways to split commands, and
 * arbitrary whitespace
 */
function getPackagesFromRunInstructions(
  runInstructions: string[],
): DockerFilePackages {
  return runInstructions.reduce((dockerfilePackages, instruction) => {
    const runDef = 'RUN ';
    const commands = instruction.slice(runDef.length).split(/\s?(;|&&)\s?/);
    const installCommands = commands.filter((command) => {
      return installRegex.test(command);
    });

    if (installCommands.length) {
      // Get the packages per install command and flatten them
      const packagesWithInstructions = installCommands.forEach((command) => {
        const packages = command
          .replace(installRegex, '')
          .replace(/-\w+/g, '')
          .trim()
          .split(/\s+/);
        packages.forEach((pkg) => {
          dockerfilePackages[pkg] = { instruction };
        });
      });
    }

    return dockerfilePackages;
  }, {});
}
