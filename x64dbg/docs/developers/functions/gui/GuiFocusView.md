# GuiFocusView

Change the active view to the given view.

```c++
void GuiFocusView(int hWindow);
```

## Parameters

`hWindow` One of the following values: GUI_DISASSEMBLY, GUI_DUMP, GUI_STACK, GUI_GRAPH, GUI_MEMMAP, GUI_SYMMOD, GUI_THREADS.

## Return Value

This function does not return a value.

## Example

```c++
GuiFocusView(GUI_DISASSEMBLY); // focus on the disassembly tab.
```

## Related functions

- List of related functions