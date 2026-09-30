#include <windows.h>
#include <stdio.h>

__declspec(dllexport) __declspec(noinline) int __cdecl patch_value(void)
{
    volatile int value = 7;
    return value;
}

int main(void)
{
    int value = patch_value();
    FILE* stream = fopen("patch_canary_result.txt", "w");
    if(!stream)
        return 2;
    fprintf(stream, "value=%d\n", value);
    fclose(stream);
    return value;
}
