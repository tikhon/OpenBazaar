import os
import sys

def main():

    path = os.path.dirname(os.path.realpath(sys.argv[0]))
    os.environ["PATH"] = "%s;%s\gpg\gpg;%s" % (path, path, os.environ["PATH"])
    sys.argv.append('start')
    sys.path.append(os.path.join(path,"pycountry-1.8-py2.7.egg"))
    from node import openbazaar
    openbazaar.main()

if __name__ == '__main__':
    main()
