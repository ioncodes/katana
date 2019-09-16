from katana import utils
import pydis

class Gadgets():
    def __init__(self):
        self.bytes = []
        self.gadgets = []
        self.is_x64 = True

    def load_file(self, path):
        with open(path, "rb") as file:
            self.bytes = file.read()
        self.is_x64 = utils.is_x64(path)
    
    def resolve(self, addr, depth):
        _gadgets = []
        for i in range(0, 100):
            if addr - i <= 0: break
            if len(_gadgets) >= depth: break
            pointer = utils.get_base_address() + addr - i
            _bytes = self.bytes[addr - i:addr + 1]
            try:
                for instruction in pydis.decode(_bytes, pointer):
                    str(instruction) # force exception if any
                _gadgets.append((_bytes, pointer))
            except:
                pass
        self.gadgets.extend(_gadgets)
    
    def match_jump(self, addr, depth):
        if self.bytes[addr - 1] != 0x00 and self.bytes[addr - 1] != 0x30 and self.bytes[addr] == 0xc3: # ret
            self.resolve(addr, depth)
        elif self.bytes[addr] == 0x0f and self.bytes[addr + 1] == 0x05: # syscall
            self.resolve(addr + 1, depth)
    
    def find_all(self, depth=6):
        self.gadgets = []
        for i in range(0, len(self.bytes)):
            self.match_jump(i, depth=depth)
        self.clean()
    
    def clean(self):
        cleaned = []
        for (gadget, pointer) in self.gadgets:
            gadgets = []
            instructions = pydis.decode(gadget, pointer)
            for instruction in instructions:
                gadgets.append(str(instruction))
            if len(gadgets) > 0 and (gadgets[-1].startswith("ret") or gadgets[-1].startswith("syscall")):
                cleaned.append((gadget, pointer))
        self.gadgets = cleaned
        self.remove_duplicates()
    
    def remove_duplicates(self):
        dupes = set()
        self.gadgets = [(gadget, _) for gadget, _ in self.gadgets if not (gadget in dupes or dupes.add(gadget))] 

    def __str__(self):
        text = ""
        for (gadget, pointer) in self.gadgets:
            gadgets = []
            instructions = pydis.decode(gadget, pointer)
            for instruction in instructions:
                gadgets.append(str(instruction))
            if len(gadgets) > 0:
                text += "0x%x: %s;\n" % (pointer, "; ".join(gadgets).lower())
        return text.strip()
    
    def __len__(self):
        return len(self.gadgets)