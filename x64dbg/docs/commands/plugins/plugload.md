# plugload/pluginload/loadplugin

Load a plugin.

## arguments

`arg1` Plugin name or plugin path.

Accepted forms:

- plugin name, using the normal plugins directory lookup
- direct `.dp32` / `.dp64` path
- optional directory shorthand, which resolves only:
  - `<dir>\<basename(dir)>.dp32`
  - `<dir>\<basename(dir)>.dp64`

## result

This command does not set any result variables.  