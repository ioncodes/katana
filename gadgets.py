import utils
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
    
    def resolve(self, addr):
        _gadgets = []
        for i in range(0, 100):
            if addr - i <= 0: break
            if len(_gadgets) >= 6: break
            pointer = utils.get_base_address() + addr - i
            _bytes = self.bytes[addr - i:addr + 1]
            try:
                for instruction in pydis.decode(_bytes, pointer):
                    str(instruction) # force exception if any
                _gadgets.append((_bytes, pointer))
            except:
                pass
        self.gadgets.extend(_gadgets)
    
    def find_all(self):
        for i in range(0, len(self.bytes)):
            if self.bytes[i] == 0xc3:
                self.resolve(i)

    def __str__(self):
        text = ""
        for (gadget, pointer) in self.gadgets:
            gadgets = []
            instructions = pydis.decode(gadget, pointer)
            for instruction in instructions:
                gadgets.append(str(instruction))
            if len(gadgets) > 0:
                text += "0x%x: %s;\n" % (pointer, "; ".join(gadgets))
        return text.strip()