# scriptrun

Run the currently loaded script from the current position.

## arguments

`arg1` (optional) Line number to stop execution at. If not provided, the script runs until completion.

## result

This command does not set any result variables.

## execution behavior

This command blocks until the script completes execution, reaches the specified stop line, encounters an error, or is manually aborted. Script execution is handled by a single dedicated thread, ensuring that only one script runs at a time.

## prerequisites

A script must be loaded using [scriptload](scriptload.md) before using this command.

## notes

- Only one script can run at a time
- Execution starts from the current script instruction pointer
- The script instruction pointer is automatically managed during execution
- Use [scriptabort](scriptabort.md) to stop a running script
