# GuiExecuteOnGuiThreadEx

Execute a callback function on the GUI thread. The callback function has a user-defined parameter.

```c++
typedef void (*GUICALLBACKEX)(void*);

void void GuiExecuteOnGuiThreadEx(GUICALLBACKEX cbGuiThread, void* userdata);
```

## Parameters

`cbGuiThread` A function pointer to the callback function.

`userdata` A user-defined parameter that is passed to the callback function.

## Return Value

This function does not return a value.

## Example

```c++
Example code.
```

## Related functions

- [GuiExecuteOnGuiThread](./GuiExecuteOnGuiThread.md)