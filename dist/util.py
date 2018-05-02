import sys

# Install Python from https://www.python.org.
(sys.version_info[0:2] >= (3, 5))   or sys.exit('error: script requires Python 3.5 or above')

import os
import re
import shutil
import stat
import subprocess

from glob import glob
from datetime import datetime


def glob_paths(patterns):
    ret = []
    for p in patterns:
        batch = glob(p.replace('/', '\\'))
        if len(batch) == 0:
            sys.exit('error: pattern matched no files: {}'.format(p))
        ret.extend(batch)
    return ret


def rmpath(path):
    if os.path.islink(path):
        os.remove(path)
    elif os.path.isfile(path):
        # MSYS2 makes files read-only, and we need this chmod command to delete
        # them.
        os.chmod(path, stat.S_IWRITE)
        os.remove(path)
    elif os.path.isdir(path):
        for child in os.listdir(path):
            # listdir excludes '.' and '..'
            rmpath(os.path.join(path, child))
        os.rmdir(path)



def mkdirs(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def getGppVer(path):
    txt = subprocess.check_output([path, '--version']).decode()
    txt = txt.splitlines()[0]
    m = re.match(r'g\+\+ \(GCC\) (\d+\.\d+\.\d+)$', txt)
    if not m:
        sys.exit('error: g++ version did not match pattern: {}'.format(repr(txt)))
    return m.group(1)


buildTimeStamp = datetime.now().strftime('%Y%m%d')
projectDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
