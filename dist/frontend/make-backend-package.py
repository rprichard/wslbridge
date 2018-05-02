#!/usr/bin/env python3
import os
import sys
sys.path.insert(1, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import util

import shutil

from os.path import abspath
from subprocess import check_call
from util import projectDir, rmpath, mkdirs

sys.platform == 'linux' or sys.exit('error: script only runs on Linux')
shutil.which('git')     or sys.exit('error: git missing')
shutil.which('make')    or sys.exit('error: make missing')
shutil.which('tar')     or sys.exit('error: tar missing')

buildDir = os.path.join(projectDir, 'out', 'build-backend')
artifactDir = os.path.join(projectDir, 'out', 'artifact')

rmpath(buildDir)
mkdirs(buildDir)
mkdirs(artifactDir)

os.chdir(buildDir)

prebuiltUrl = 'https://github.com/rprichard/x86_64-linux-glibc2.15-4.8.git'
prebuiltPath = abspath('linux-prebuilt')
artifactPath = os.path.join(artifactDir, 'backend.tar.gz')

check_call(['git', 'clone', prebuiltUrl, prebuiltPath])

os.putenv('CXX',   os.path.join(prebuiltPath, 'bin', 'x86_64-linux-g++'))
os.putenv('STRIP', os.path.join(prebuiltPath, 'bin', 'x86_64-linux-strip'))
check_call(['make', 'clean'], cwd=os.path.join(projectDir, 'backend'))
check_call(['make'],          cwd=os.path.join(projectDir, 'backend'))
check_call(['tar', 'cfa', artifactPath, '-C', '..', 'wslbridge-backend'])
