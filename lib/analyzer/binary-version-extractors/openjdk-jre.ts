import { Docker } from '../../docker';
import { Binary } from '../types';

export {
  extract,
  packageNames,
};

// todo: add common names such as 'java-common'
const packageNames = ['java'];

async function extract(targetImage: string): Promise<Binary | null> {
  try {
    const binaryVersion = await new Docker(targetImage).
      run('java', [ '-version' ]);
    return parseOpenJDKBinary(binaryVersion);
  } catch (stderr) {
    if (typeof stderr === 'string' && stderr.indexOf('not found') >= 0) {
      return null;
    }
    throw new Error(stderr);
  }
}

function parseOpenJDKBinary(fullVersionOutput: string) {
  /*
  `java -version` output:
  `java version "1.8.0_191"
   Java(TM) SE Runtime Environment (build 1.8.0_191-b12)
   Java HotSpot(TM) 64-Bit Server VM (build 25.191-b12, mixed mode)`
  => extracting `1.8.0_191-b12`
  */
  const jdkVersionLines = fullVersionOutput &&
                          fullVersionOutput.trim().split('\n');
  if (!jdkVersionLines || jdkVersionLines.length !== 3) {
    return null;
  }
  const bracketsRE = /\(build (.*)\)$/;
  const buildVersion = jdkVersionLines[1].match(bracketsRE);
  const version = buildVersion && buildVersion[1];
  if (!version) {
    return null;
  }
  return {
    name: 'openjdk-jre',
    version,
  };
}
