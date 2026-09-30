# DbgValSetScalar

Set a scalar value.

Previously this function was called `DbgValToString`.

```c++
bool DbgValSetScalar(const char* string, duint value);
```

## Parameters

`string` The name of the thing to set in UTF-8 encoding.

`value` The scalar value to set.

## Return Value

`true` if the value was set successfully, `false` otherwise.

## Example

```c++
DbgValSetScalar("eax", 1);
```

## Related functions

- [DbgValFromString](./DbgValFromString.md)
- [DbgValSetBuffer](./DbgValSetBuffer.md)
