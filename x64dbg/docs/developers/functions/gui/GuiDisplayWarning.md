# GuiDisplayWarning

Shows a warning dialog with title text and main message text.

```c++
void GuiDisplayWarning(const char* title, const char* text)
```

## Parameters

`title` Dialog title in UTF-8 encoding.

`text` Dialog text in UTF-8 encoding.

## Return Value

This function does not return a value.

## Example

```c++
GuiDisplayWarning("Warning!", "Operation cannot be reversed.");
```

## Related functions

- [GuiAddLogMessage](./GuiAddLogMessage.md)
- [GuiAddStatusBarMessage](./GuiAddStatusBarMessage.md)