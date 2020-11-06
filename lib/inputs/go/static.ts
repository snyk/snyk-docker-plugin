import * as elf_tools from "elf-tools";
import { getContentAsBuffer } from "../../extractor";
import { ExtractAction, ExtractedLayers } from "../../extractor/types";
import { streamToBuffer } from "../../stream-utils";

// we want to exclude /bin, /lib, /sbin, /usr, /var
export const getGoFileContentAction: ExtractAction = {
  actionName: "traefik",
  filePathMatches: (filePath: string) => filePath.includes("traefik"), // very tmp for testing
  callback: streamToBuffer,
};
export async function extractGoModules(
  extractedLayers: ExtractedLayers,
): Promise<string[]> {
  const goBinaryContentBuffer = getContentAsBuffer(
    extractedLayers,
    getGoFileContentAction,
  );
  const parsedSections: string[] = [];
  // from buffer now we have to first determine which executable we're dealing with, in this example it's elf:
  // executables build for go: ELF, Mach-O, PE, XCOFF
  // ELF binary will always start with \x7FELF mandatory header
  const executableType = goBinaryContentBuffer?.toString("utf8", 0, 16);
  // Buffer.from('\x7fELF', 'ascii');
  if (!(executableType && executableType.includes("ELF"))) {
    return [];
  }

  // parse elf file for go headers
  // parse the data
  const elf = elf_tools.parse(goBinaryContentBuffer);

  // elf.Sections .go.buildinfo

  elf.sections.forEach((section) => {
    if (section.header.name !== ".go.buildinfo") {
      return;
    }

    const addr = section.header.addr; // 84676608;
    const offset = section.header.offset; // 80482304

    const programSection = elf.programs.find(
      (program) =>
        program.header.offset === offset && program.header.vaddr === addr,
    );
    // from segment data below we need to extract go modules info and push into parsedSections array
    const segmentData: Buffer = programSection.data;

    // The build info blob left by the linker is identified by
    // a 16-byte header, consisting of buildInfoMagic (14 bytes),
    // the binary's pointer size (1 byte),
    // and whether the binary is big endian (1 byte).

    // Everything below is just testing & trying things for now
    const buildInfoMagic = segmentData.toString("ascii", 0, 16);
    JSON.stringify(buildInfoMagic);

    // Data section starts with
    // "\xff Go buildinf:"

    // pointer size
    const ptrSize = segmentData[14];
    JSON.stringify(ptrSize);
  });

  return parsedSections;
}
