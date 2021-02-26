import {
  Arg,
  Dockerfile,
  DockerfileParser,
  From,
  Instruction,
  Keyword,
} from "dockerfile-ast";
import { EOL } from "os";

interface ImageResolution {
  image: string;
  instructions: Instruction[];
}

function resolveImage(stage: From, dockerfile: Dockerfile): ImageResolution {
  // build a stage alias index
  const list = dockerfile.getFROMs().map((from) => {
    return {
      alias: from.getBuildStage(),
      stage: from,
    };
  });
  const alias: Record<string, From> = list
    .filter((meta) => meta.alias !== null)
    .reduce((result, current) => {
      result[current.alias] = current.stage;
      return result;
    }, {});

  // discover the instruction path from the stage to the root
  const instructions = [];
  let pointer = stage;

  do {
    // save
    instructions.push(pointer);

    // try find aliased instruction
    const image = pointer.getImage();
    const instruction = alias[image];

    // if no aliased instruction found
    if (!instruction) {
      // try find variable
      const variables = pointer.getVariables();

      if (variables.length > 1) {
        throw new Error("diverging paths detected.");
      }

      const variable = variables[0];
      if (variable !== undefined) {
        const args = dockerfile
          .getARGs()
          .filter((arg) => arg.getProperty().getName() === variable.getName());
        const arg = args[0];
        instructions.push(arg);
      }
    }

    // move on to next instruction...
    pointer = instruction;
  } while (pointer);

  // get image from last instruction....
  const lastInstruction = instructions[instructions.length - 1];
  let image;
  if (lastInstruction.getKeyword() === Keyword.FROM) {
    image = (lastInstruction as From).getImage();
  } else if (lastInstruction.getKeyword() === Keyword.ARG) {
    image = (lastInstruction as Arg).getProperty().getValue();
  }

  return {
    image,
    instructions,
  };
}

describe("base image parsing", () => {
  it.each`
    scenario                      | content                     | expected
    ${"image"}                    | ${"FROM repo"}              | ${"repo"}
    ${"image with alias"}         | ${"FROM repo as alias"}     | ${"repo"}
    ${"image with tag"}           | ${"FROM repo:tag"}          | ${"repo:tag"}
    ${"image with tag and alias"} | ${"FROM repo:tag AS alias"} | ${"repo:tag"}
  `("resolves single line $scenario", ({ content, expected }) => {
    const dockerfile = DockerfileParser.parse(content);
    const stage = dockerfile.getFROMs()[0];
    const result = resolveImage(stage, dockerfile);

    expect(result.image).toBe(expected);
    expect(result.instructions[0].getKeyword()).toBe(Keyword.FROM);
  });

  it.each`
    scenario   | content                                                            | stage | expected  | instructions
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo"}                           | ${0}  | ${"repo"} | ${1}
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo"}                           | ${1}  | ${"repo"} | ${2}
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo AS bar" + EOL + "FROM bar"} | ${0}  | ${"repo"} | ${1}
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo AS bar" + EOL + "FROM bar"} | ${1}  | ${"repo"} | ${2}
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo AS bar" + EOL + "FROM bar"} | ${2}  | ${"repo"} | ${3}
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo AS bar" + EOL + "FROM baz"} | ${2}  | ${"baz"}  | ${1}
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo AS baz" + EOL + "FROM foo"} | ${2}  | ${"repo"} | ${2}
  `(
    "resolves multi stage alias line $scenario",
    ({ content, stage, expected, instructions }) => {
      const dockerfile = DockerfileParser.parse(content);
      const from = dockerfile.getFROMs()[stage];
      const result = resolveImage(from, dockerfile);

      expect(result.image).toBe(expected);
      expect(result.instructions).toHaveLength(instructions);
    },
  );

  it.each`
    scenario   | content                                  | stage | expected  | instructions
    ${"image"} | ${"FROM repo AS foo" + EOL + "FROM foo"} | ${0}  | ${"repo"} | ${1}
    ${"image"} | ${"FROM repo as foo" + EOL + "FROM foo"} | ${0}  | ${"repo"} | ${1}
  `(
    "resolves multi stage alias line with without case sensitivity $scenario",
    ({ content, stage, expected, instructions }) => {
      const dockerfile = DockerfileParser.parse(content);
      const from = dockerfile.getFROMs()[stage];
      const result = resolveImage(from, dockerfile);

      expect(result.image).toBe(expected);
      expect(result.instructions).toHaveLength(instructions);
    },
  );

  it.each`
    scenario        | content                                     | stage | expected  | instructions
    ${"with {}"}    | ${"ARG IMAGE=repo" + EOL + "FROM ${IMAGE}"} | ${0}  | ${"repo"} | ${2}
    ${"without {}"} | ${"ARG IMAGE=repo" + EOL + "FROM $IMAGE"}   | ${0}  | ${"repo"} | ${2}
  `("resolves args $scenario", ({ content, stage, expected, instructions }) => {
    const dockerfile = DockerfileParser.parse(content);
    const from = dockerfile.getFROMs()[stage];
    const result = resolveImage(from, dockerfile);

    expect(result.image).toBe(expected);
    expect(result.instructions).toHaveLength(instructions);
  });

  it.each`
    scenario   | content                                                                                    | stage | expected  | instructions
    ${"image"} | ${"ARG IMAGE=repo" + EOL + "ARG FIZZ=buzz" + EOL + "FROM ${FIZZ}" + EOL + "FROM ${IMAGE}"} | ${0}  | ${"buzz"} | ${2}
    ${"image"} | ${"ARG IMAGE=repo" + EOL + "ARG FIZZ=buzz" + EOL + "FROM ${FIZZ}" + EOL + "FROM ${IMAGE}"} | ${1}  | ${"repo"} | ${2}
  `(
    "resolves multi stage args $scenario",
    ({ content, stage, expected, instructions }) => {
      const dockerfile = DockerfileParser.parse(content);
      const from = dockerfile.getFROMs()[stage];
      const result = resolveImage(from, dockerfile);

      expect(result.image).toBe(expected);
      expect(result.instructions).toHaveLength(instructions);
    },
  );

  /**
   * Updating multi arg stage is impractical as it may lead to scenarios that involves adding or removing ARGS based on our recommendations.
   */
  it.each`
    scenario             | content
    ${"multi arg stage"} | ${"ARG IMAGE=repo" + EOL + "ARG FIZZ=buzz" + EOL + "FROM ${IMAGE}:${FIZZ}"}
  `("throws error on $scenario", ({ content, stage }) => {
    const dockerfile = DockerfileParser.parse(content);
    const from = dockerfile.getFROMs()[stage];
    expect(() => resolveImage(from, dockerfile)).toThrowError();
  });
});
