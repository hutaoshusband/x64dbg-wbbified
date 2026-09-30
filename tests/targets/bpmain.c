#include <windows.h>
#include <stdio.h>

volatile unsigned g_hits;

__declspec(dllexport) __declspec(noinline) void __cdecl brk_target(void)
{
    g_hits++;
}

int main(int argc, char* argv[])
{
    const char* out = argc > 1 ? argv[1] : "bpmain_result.txt";
    brk_target();
    brk_target();
    FILE* f = fopen(out, "w");
    if(!f)
        return 2;
    fprintf(f, "marker=done\nhits=%u\n", g_hits);
    fclose(f);
    return 0;
}
