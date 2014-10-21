from distutils.core import setup
import os
import sys

import py2exe
import pycountry
import zmq
import zmq.libzmq

setup_dir = os.path.dirname(os.path.realpath(__file__))
root_dir = os.path.dirname(os.path.dirname(setup_dir))
pycountry_dir = os.path.dirname(pycountry.__file__)
zmq_dir = os.path.dirname(zmq.__file__)

# py2exe depedency detecion is quite problematic
sys.path.insert(0, zmq_dir) #for libzmq.pyd
sys.path.insert(0, root_dir) #for node
sys.path.insert(0, setup_dir) #for local openbazaar.py

def tree(root_dir, l, dest):
    """
    Create a list with all files root_dir and its subfolders in an appropriate
    format for distutils data_files
    """
    prefix = os.path.dirname(root_dir)
    for (root, _, files) in os.walk(os.path.normpath(root_dir)):
        l.append((dest+root[len(prefix):], [root+'\\'+file for file in files]))

data_files = []
tree(root_dir + "\\html", data_files, ".")
tree(pycountry_dir+"\\databases", data_files, "pycountry\\")
tree(pycountry_dir+"\\locales", data_files, "pycountry\\")


setup(
    console=[
        {
            'script': 'openbazaar.py',
            'icon_resources': [(1, 'icon.ico')]
        },
        {
            'script': 'stop.py'
        }
    ],
    options=
    {
        "py2exe":
        {
            'dist_dir': 'dist_exe',
            'bundle_files': 3,
            'compressed': 2,
            'optimize': 2,
            'includes': ["zmq.utils", "zmq.utils.jsonapi", "zmq.utils.strtypes", "zmq.backend.cython"],

            #HACK: py2exe copies libzmq.pyd with the wrong name zmq.libzmq.pyd
            #Manually excluding zmq.libzmq.pyd copies it with the right name
            'excludes': ['zmq.libzmq'],
            'dll_excludes':['IPHLPAPI.DLL', 'PSAPI.DLL', 'WTSAPI32.dll', 'w9xpopen.exe']
        }
    },
    data_files=data_files
)
