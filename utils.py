from elftools.elf.elffile import ELFFile

def is_x64(file):
    f = open(file, "rb")
    elf = ELFFile(f)
    return elf["e_ident"]["EI_CLASS"] != "ELFCLASS32"

def is_x86(file):
    f = open(file, "rb")
    elf = ELFFile(f)
    return elf["e_ident"]["EI_CLASS"] == "ELFCLASS32"

def get_base_address():
    return 0x400000