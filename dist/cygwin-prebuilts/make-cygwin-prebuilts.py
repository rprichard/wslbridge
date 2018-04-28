#!python3
import os
import re
import shutil
import subprocess
import sys
import urllib

import dllversion

from datetime import datetime
from glob import glob
from os import getcwd, chdir
from os.path import abspath
from subprocess import call, check_call


# Install https://www.python.org, https://www.7-zip.org. Use Win10 bundled curl.
(sys.version_info[0:2] >= (3, 6))   or sys.exit('script requires Python 3.6 or above')
sys.platform == 'win32'             or sys.exit('script only runs on Windows (no Cygwin/MSYS)')
shutil.which('7z')                  or sys.exit('7z missing')
shutil.which('curl')                or sys.exit('curl missing')


def glob_paths(patterns):
    ret = []
    for p in patterns:
        batch = glob(p.replace('/', '\\'))
        if len(batch) == 0:
            sys.exit('error: pattern matched no files: {}'.format(p))
        ret.extend(batch)
    return ret


def getGccVer(path):
    txt = subprocess.check_output([path, '--version']).decode()
    txt = txt.splitlines()[0]
    m = re.match(r'g\+\+ \(GCC\) (\d+\.\d+\.\d+)$', txt)
    if not m:
        sys.exit('error: GCC version did not match pattern: {}'.format(repr(txt)))
    return m.group(1)


def rmpath(path):
    if os.path.islink(path) or os.path.isfile(path):
        os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)

def mkdirs(path):
    if not os.path.isdir(path):
        os.makedirs(path)


buildTimeStamp = datetime.now().strftime('%Y%m%d')
projectDir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
buildDir = os.path.join(projectDir, 'out\\build-cygwin')
artifactDir = os.path.join(projectDir, 'out\\artifact')

print(buildDir)
print(artifactDir)

rmpath(buildDir)
mkdirs(buildDir)
mkdirs(artifactDir)

os.chdir(buildDir)

for setup, cygwin in (('setup-x86_64', 'cygwin64'), ('setup-x86', 'cygwin')):

    check_call(['curl', '-O', 'https://cygwin.com/{}.exe'.format(setup)])

    check_call([
        abspath('{}.exe'.format(setup)),
        '-l', abspath('{}-packages'.format(cygwin)),
        '-P', 'gcc-g++,make',
        '-s', 'http://mirrors.xmission.com/cygwin',
        '-R', abspath(cygwin),
        '--no-admin', '--no-desktop', '--no-shortcuts', '--no-startmenu', '--quiet-mode',
    ])

    cygVer = dllversion.fileVersion('{}/bin/cygwin1.dll'.format(cygwin))
    gccVer = getGccVer('{}/bin/g++.exe'.format(cygwin))

    filename = '{}\\{}-{}-dll{}-gcc{}.7z'.format(artifactDir, cygwin, buildTimeStamp, cygVer, gccVer)
    rmpath(filename)

    check_call(['7z', 'a', filename] + glob_paths([
        cygwin + '/bin',
        cygwin + '/dev',
        cygwin + '/lib',
        cygwin + '/tmp',
        cygwin + '/usr/include',
        cygwin + '/usr/*-pc-cygwin',
    ]))
