# scriptcmd

Execute a command in the context of a running script.

## arguments

Unlike other commands this command forwards everything after `scriptcmd ` directly to the command processor.

For example `scriptcmd add rax, 0x1245` will execute the command `add rax, 0x1234`.

## result

This command does not set any result variables.

## execution behavior

This command blocks until the specified command completes execution. Script execution is handled by a single dedicated thread, ensuring commands execute in the order they are submitted without interference from other operations.

## example

This command can be used in combination with [SetBreakpointCommand](../conditional-breakpoint-control/SetBreakpointCommand.md) to execute scripts on breakpoint callbacks:

```
fn_addr = module.dll:$0x1234 // module.dll RVA 0x1234
bp fn_addr
SetBreakpointCommand fn_addr, "scriptcmd call mycallback"

// TODO: make sure the script is not unloaded (using run)

mycallback:
log "fn({arg.get(0)}, {arg.get(1)})"
ret
```
