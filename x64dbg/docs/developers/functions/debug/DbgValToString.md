# DbgValToString

Legacy name for `DbgValSetScalar` kept for binary compatibility.

`DbgValToString` is no longer part of the public bridge header. Use [DbgValSetScalar](./DbgValSetScalar.md) instead.

```c++
bool DbgValToString(const char* string, duint value);
```

## Parameters

`string` The name of the thing to set in UTF-8 encoding.

`value` The value to set.

## Return Value

`true` if the value was set successfully, `false` otherwise.

## Example

```c++
DbgValToString("eax", 1);
```

## Related functions

- [DbgValFromString](./DbgValFromString.md)
- [DbgValSetScalar](./DbgValSetScalar.md)