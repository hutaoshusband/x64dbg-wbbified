# GuiScriptAdd

Reload the script view with a new script.

```c++
void GuiScriptAdd(int count, const char** lines);
```

## Parameters

`count` Number of lines;

`lines` A buffer containing `count` pointers to UTF-8 strings, each representing a single line. This buffer is freed by [BridgeFree](../bridge/BridgeFree.md) afterwards.

## Return Value

This function does not return a value.

## Example

```c++
Example code.
```

## Related functions

- List of related functions