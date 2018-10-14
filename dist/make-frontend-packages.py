#!python3
import util

import os
import shutil
import sys

from os.path import abspath, relpath
from subprocess import check_call
from util import projectDir, rmpath, mkdirs

sys.platform == 'win32' or sys.exit('error: script only runs on Windows (no Cygwin/MSYS)')
shutil.which('7z')      or sys.exit('error: 7z missing')
shutil.which('curl')    or sys.exit('error: curl missing')

buildDir = os.path.join(projectDir, 'out', 'build-frontend')
artifactDir = os.path.join(projectDir, 'out', 'artifact')

rmpath(buildDir)
mkdirs(buildDir)
mkdirs(artifactDir)

os.chdir(buildDir)

baseUrl = 'https://github.com/rprichard/wslbridge/raw/wslbridge-cygwin-prebuilts-1.0.7/'

for platform, binDir, url in [
            ('cygwin32', 'bin',     baseUrl + 'cygwin32-20180502-dll2.10.0-gcc6.4.0.7z'),
            ('cygwin64', 'bin',     baseUrl + 'cygwin64-20180502-dll2.10.0-gcc6.4.0.7z'),
            ('msys32',   'usr/bin', baseUrl + 'msys32-20180502-dll2.10.0-gcc7.3.0.7z'),
            ('msys64',   'usr/bin', baseUrl + 'msys64-20180502-dll2.10.0-gcc7.3.0.7z'),
        ]:

    if os.getenv('CYGWIN_VARIANT') and os.getenv('CYGWIN_VARIANT') != platform:
        continue

    print('Building {} ...'.format(platform))

    check_call(['curl', '-fL', url, '-o', '{}.7z'.format(platform)])
    check_call(['7z', 'x', '{}.7z'.format(platform)])

    platformBinDir = abspath(os.path.join(platform, binDir))
    artifactPath = os.path.join(artifactDir, '{}-frontend.tar.gz'.format(platform))

    origPATH = os.getenv('PATH')
    os.putenv('PATH', platformBinDir + os.pathsep + origPATH)
    # Rebase the binaries after installing/moving them onto the new machine.
    check_call([os.path.join(platformBinDir, 'ash.exe'), '/{}/rebaseall'.format(binDir), '-v'])
    check_call([os.path.join(platformBinDir, 'make.exe'), 'clean'], cwd=os.path.join(projectDir, 'frontend'))
    check_call([os.path.join(platformBinDir, 'make.exe')],          cwd=os.path.join(projectDir, 'frontend'))
    check_call([os.path.join(platformBinDir, 'tar.exe'), 'cfa',
                relpath(artifactPath, os.getcwd()).replace('\\', '/'),
                '-C', '..', 'wslbridge.exe'])
    os.putenv('PATH', origPATH)
