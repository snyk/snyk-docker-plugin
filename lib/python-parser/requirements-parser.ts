import { parseExtraNames, specifierValidRange } from "./common";
import { PythonRequirement } from "./types";

// This looks like a crazy regex, but it's long because of the named capture groups
// which make the result easier to read. It essentially breaks each line into name,
// specifier and version, where only the name is mandatory
const VERSION_PARSE_REGEX =
  /^(?<name>[\w.-]+)((\[(?<extras>.*)\])?)((?<specifier><|<=|!=|==|>=|>|~=|===)(?<version>[\w.]*))?/;

export function getRequirements(fileContent: string): PythonRequirement[] {
  const lines = fileContent.split("\n");
  const parsedLines = lines.map(parseLine).filter((res) => res !== null);
  return parsedLines as PythonRequirement[];
}

function parseLine(line: string): PythonRequirement | null {
  line = line.trim();
  // there's no point in calling the regex if the line is a comment
  if (line.length === 0 || line.startsWith("#")) {
    return null;
  }
  const parsedLine = VERSION_PARSE_REGEX.exec(line);
  if (!parsedLine?.groups) {
    return null;
  }
  const { name, extras, specifier, version } = parsedLine.groups;
  return {
    name: name.toLowerCase(),
    specifier: specifierValidRange(specifier, version),
    version,
    extras: parseExtraNames(extras),
  } as PythonRequirement;
}
