# GuiExecuteOnGuiThread

Execute a callback function on the GUI thread.

```c++
typedef void (*GUICALLBACK)();

void GuiExecuteOnGuiThread(GUICALLBACK cbGuiThread);
```

## Parameters

`cbGuiThread` A function pointer to the callback function.

## Return Value

This function does not return a value.

## Example

```c++
Example code.
```

## Related functions

- [GuiExecuteOnGuiThreadEx](./GuiExecuteOnGuiThreadEx.md)