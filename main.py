from katana.gadgets import Gadgets
import sys

if __name__ == "__main__":
    _gadgets = Gadgets(mode="ctf")
    _gadgets.load_file(sys.argv[1])
    _gadgets.find_all(depth=8)
    print(_gadgets)
    print("Found %i gadgets!" % len(_gadgets))