import { readFileSync } from "fs";
import * as path from "path";
import * as ts from "typescript";

const repoRoot = path.join(__dirname, "../..");

// Tests are not type-checked (ts-jest runs with isolatedModules), so the
// union members are read from the source rather than from the type.
function factTypesInTypeScript(): string[] {
  const typesPath = path.join(repoRoot, "lib/types.ts");
  const source = ts.createSourceFile(
    typesPath,
    readFileSync(typesPath, "utf8"),
    ts.ScriptTarget.Latest,
  );
  const factType = source.statements.find(
    (statement): statement is ts.TypeAliasDeclaration =>
      ts.isTypeAliasDeclaration(statement) &&
      statement.name.text === "FactType",
  );
  if (!factType || !ts.isUnionTypeNode(factType.type)) {
    throw new Error("lib/types.ts does not declare FactType as a union");
  }
  return factType.type.types.map((member) => {
    if (!ts.isLiteralTypeNode(member) || !ts.isStringLiteral(member.literal)) {
      throw new Error("FactType has a member that is not a string literal");
    }
    return member.literal.text;
  });
}

function factTypesInOpenApi(): string[] {
  const lines = readFileSync(
    path.join(repoRoot, "components/common.yaml"),
    "utf8",
  ).split(/\r?\n/);
  const factType = lines.indexOf("  FactType:");
  const enumStart = lines.indexOf("    enum:", factType);
  if (factType === -1 || enumStart === -1) {
    throw new Error("components/common.yaml has no schemas.FactType.enum");
  }
  const values: string[] = [];
  for (const line of lines.slice(enumStart + 1)) {
    const value = /^ {6}- (\S+)$/.exec(line);
    if (!value) {
      break;
    }
    values.push(value[1]);
  }
  return values;
}

describe("components/common.yaml", () => {
  it("allows every FactType the plugin emits", () => {
    const allowed = factTypesInOpenApi();
    expect(allowed.length).toBeGreaterThan(0);

    const missing = factTypesInTypeScript().filter(
      (factType) => !allowed.includes(factType),
    );

    expect(missing).toEqual([]);
  });
});
