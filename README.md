# wslbridge

wslbridge is a Cygwin program that connects to a WSL (Windows Subsystem for
Linux) pty over TCP sockets.

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

The Cygwin frontend program is written to `out/wslbridge`.  The ELF64 backend
program is written to `out/wslbridge-backend`.  The files can be copied
somewhere more convenient, but they need to be on a letter drive (e.g. not a
`\\server\share\...` UNC path).  They probably need to be on an NTFS volume.
The frontend looks for the backend in its own directory.

Run `wslbridge` to start a bash session in WSL.

## Copyright

This project is distributed under the MIT license (see the `LICENSE` file in
the project root).

By submitting a pull request for this project, you agree to license your
contribution under the MIT license to this project.
