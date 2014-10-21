import os
import sys

from node import openbazaar

def main():

    path = os.path.dirname(os.path.realpath(sys.argv[0]))
    os.environ["PATH"] = "%s;%s\gpg\gpg;%s" % (path, path, os.environ["PATH"])
    sys.argv.append('start')
    openbazaar.main()

if __name__ == '__main__':
    main()
