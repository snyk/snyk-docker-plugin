export interface Elf {
  body: {
    programs: ElfProgram[];
    sections: ElfSection[];
  };
}

export interface ElfProgram {
  type: string;
  offset: number;
  vaddr: number;
  filesz: number;
  flags: {
    w?: boolean;
  };
  data: Buffer;
}

export interface ElfSection {
  name: string;
  addr: number;
  off: number;
  size: number;
  data: Buffer;
}
