from katana import utils
from katana.signatures import *
import pydis
import threading
import concurrent.futures

class Gadgets():
    def __init__(self):
        self.bytes = []
        self.gadgets = []
        self.is_x64 = True
        self.signatures = [
            RET, SYSCALL,
            CALL_RAX, CALL_RBP, CALL_RBX, CALL_RCX, CALL_RDI, CALL_RDX, CALL_RSI, CALL_RSP,
            CALL_R8, CALL_R9, CALL_R10, CALL_R11, CALL_R12, CALL_R13, CALL_R14, CALL_R15
        ]

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
        for signature in self.signatures:
            matched = False
            for i in range(0, len(signature)):
                if addr + i >= len(self.bytes): break
                matched = self.bytes[addr + i] == signature[i]
            if matched:
                self.resolve(addr + len(signature) - 1, depth)
    
    def find_all(self, depth=6):
        self.gadgets = []
        """with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            for i in range(0, len(self.bytes)):
                executor.submit(self.match_jump, i, depth)
            executor.shutdown(wait=True)"""
        for i in range(0, len(self.bytes)):
            self.match_jump(i, depth)
        self.clean()
    
    def clean(self):
        cleaned = []
        for (gadget, pointer) in self.gadgets:
            gadgets = []
            instructions = pydis.decode(gadget, pointer)
            for instruction in instructions:
                gadgets.append(str(instruction))
            if len(gadgets) > 0 and (gadgets[-1].startswith("ret") or gadgets[-1].startswith("syscall") or gadgets[-1].startswith("call")):
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