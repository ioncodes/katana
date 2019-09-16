from katana.gadgets import Gadgets
import sys

if __name__ == "__main__":
    _gadgets = Gadgets()
    _gadgets.load_file(sys.argv[1])
    _gadgets.find_all()
    print(_gadgets)