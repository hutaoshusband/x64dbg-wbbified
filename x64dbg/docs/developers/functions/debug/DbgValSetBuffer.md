# DbgValSetBuffer

Set a value from a raw buffer.

```c++
bool DbgValSetBuffer(const char* string, const void* data, size_t size);
```

## Parameters

`string` The name of the thing to set in UTF-8 encoding.

`data` Pointer to the raw bytes to write.

`size` Size of `data` in bytes.

## Return Value

`true` if the value was set successfully, `false` otherwise.

## Example

```c++
unsigned long long opmask = 1;
DbgValSetBuffer("_K0", &opmask, sizeof(opmask));
```

## Related functions

- [DbgValFromString](./DbgValFromString.md)
- [DbgValSetScalar](./DbgValSetScalar.md)
