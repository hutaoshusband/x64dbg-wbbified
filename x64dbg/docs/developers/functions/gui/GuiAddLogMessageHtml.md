# GuiAddLogMessageHtml

Adds a message in HTML to the log. The message will be shown in the log window and on the status bar at the bottom of x64dbg.

The message is formatted in HTML, so links and color tags can be added. Remember to escape any HTML special characters when some text from the debuggee needs to be logged.

```c++
void GuiAddLogMessageHtml(
    const char* msg // string containg HTML-formatted message to add to log
    );
```

## Parameters

`msg` String containing the HTML-formatted message to add to the log. Ensure that a carriage line and return feed are included with the string for it to properly display it. Encoding is UTF-8.

## Return Value

This function does not return a value.

## Example

```c++
GuiAddLogMessageHtml("<b>This <i>formatted</i> text will be displayed in the <u>log view</u></b>.\n");
```

```nasm
.data
szMsg db "<b>This <i>formatted</i> text will be displayed in the <u>log view</u></b>",13,10,0 ; CRLF
    
.code
Invoke GuiAddLogMessageHtml, Addr szMsg
```

## Related functions

- [GuiAddLogMessage](./GuiAddLogMessage.md)
- [GuiLogClear](./GuiLogClear.md)
- [GuiAddStatusBarMessage](./GuiAddStatusBarMessage.md)