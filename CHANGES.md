# Version 0.2.1 (2016-11-14)

Changes since 0.2.0

 * The frontend now synchronizes the Cygwin environment with the Win32
   environment before creating the WSL backend process.
   https://github.com/mintty/wsltty/issues/14

# Version 0.2.0 (2016-09-28)

Changes since 0.1.0:

 * Added a `-C` option that changes the working directory before running the
   command.  The argument is a WSL path.  A `~` component at the start of the
   argument is replaced with the user's home directory.  (i.e. `$HOME`).
   [#2](https://github.com/rprichard/wslbridge/issues/2)

 * The frontend now canonicalizes its path to the `wslbridge-backend` binary.
   [#4](https://github.com/rprichard/wslbridge/issues/4)

# Version 0.1.0 (2016-08-17)

Initial release
