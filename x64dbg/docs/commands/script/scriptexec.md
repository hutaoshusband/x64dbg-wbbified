# scriptexec

Load and execute a script file in a single operation.

## arguments

`arg1` Script file path to load and execute.

## result

This command does not set any result variables.

## execution behavior

This command blocks until the script completes execution. It performs the following operations:
1. Loads the specified script file
2. Executes the script from the beginning
3. Automatically unloads the script only if execution completes successfully

Script execution is handled by a single dedicated thread, ensuring that only one script runs at a time.

## notes

- Cannot be used from within a running script
- If script execution fails or is aborted, the script remains loaded
- This is the most convenient way to run standalone scripts
- Execution always starts from the beginning of the script
- You can use the Script tab context menu to abort a running script if needed
