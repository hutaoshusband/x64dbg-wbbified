# GuiAutoCompleteAddCmd

Add a command to the auto-completion list of the command bar. This function is automatically called by x64dbg when a command is registered, therefore plugin developers do not need to call this function.

```c++
void GuiAutoCompleteAddCmd(const char* cmd);
```

## Parameters

`cmd` The command that is added to the auto-completion list of the command bar.

## Return Value

This function does not return a value.

## Related functions

- [GuiAutoCompleteDelCmd](./GuiAutoCompleteDelCmd.md)
- [GuiAutoCompleteClearAll](./GuiAutoCompleteClearAll.md)