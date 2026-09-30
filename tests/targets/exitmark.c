#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
    const char* out = argc > 1 ? argv[1] : "exitmark_result.txt";
    FILE* f = fopen(out, "w");
    if(!f)
        return 2;
    fputs("marker=done\n", f);
    fclose(f);
    return 42;
}
