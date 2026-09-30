#include <windows.h>
#include <stdio.h>

#ifdef _WIN64
#define GET_PEB() ((unsigned char*)__readgsqword(0x60))
#define PEB_GLOBAL_FLAGS_OFFSET 0xBC
#define PEB_HEAP_OFFSET 0x30
#define HEAP_FLAGS_OFFSET 0x70
#else
#define GET_PEB() ((unsigned char*)__readfsdword(0x30))
#define PEB_GLOBAL_FLAGS_OFFSET 0x68
#define PEB_HEAP_OFFSET 0x18
#define HEAP_FLAGS_OFFSET 0x40
#endif

int main(int argc, char* argv[])
{
    unsigned char* peb = GET_PEB();
    unsigned char beingDebugged = peb[2];
    unsigned int ntGlobalFlag = *(unsigned int*)(peb + PEB_GLOBAL_FLAGS_OFFSET);
    unsigned int heapFlags = 0;
    unsigned char* heap = *(unsigned char**)(peb + PEB_HEAP_OFFSET);
    if(heap)
        heapFlags = *(unsigned int*)(heap + HEAP_FLAGS_OFFSET);
    const char* out = argc > 1 ? argv[1] : "probe_result.txt";
    FILE* f = fopen(out, "w");
    if(!f)
        return 2;
    fprintf(f, "BeingDebugged=%u\nNtGlobalFlag=0x%x\nHeapFlags=0x%x\n",
            beingDebugged, ntGlobalFlag, heapFlags);
    fclose(f);
    return 0;
}
