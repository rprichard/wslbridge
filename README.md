# wslbridge

wslbridge is a Cygwin program that allows connecting to the WSL command-line
environment over TCP sockets, as with ssh, but without the overhead of
configuring an SSH server.

## Building wslbridge

You'll need a Cygwin (32 or 64 bit) environment, as well as a WSL environment
(or any other Linux environment).  Make sure you have the g++ and make packages
installed.

In Cygwin:

    $ cd frontend
    make

In WSL/Linux:

    $ cd backend
    make

The Cygwin frontend program is written to `out/wslbridge.exe`.  The ELF64
backend program is written to `out/wslbridge-backend`.  The files can be copied
somewhere more convenient, but they need to be on a letter drive (e.g. not a
`\\server\share\...` UNC path).  They also need to be on an NTFS volume.  The
frontend looks for the backend in its own directory.

## Usage

Usage is similar to that of `ssh`.  Run `wslbridge` with no arguments to start
a bash session in a WSL pty.  Append a command-line to run that command in WSL
without a pty (i.e. using 3 pipes for stdio).

`wslbridge` runs its WSL command with either a pty or using pipes.  Pass `-t`
to enable pty mode or `-T` to enable pipe mode.  Pass `-t -t` to force pty mode
even if stdin is not a terminal.

Pass `-eVAR=VAL` to set an environment variable within WSL.  Pass just `-eVAR`
to copy the value from the Cygwin environment.

## Copyright

This project is distributed under the MIT license (see the `LICENSE` file in
the project root).

By submitting a pull request for this project, you agree to license your
contribution under the MIT license to this project.
