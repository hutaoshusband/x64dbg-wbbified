#include <windows.h>
#include <stdio.h>

#ifdef _WIN64
#define GET_PEB() ((unsigned char*)__readgsqword(0x60))
#else
#define GET_PEB() ((unsigned char*)__readfsdword(0x30))
#endif

int main(int argc, char* argv[])
{
    unsigned char* peb = GET_PEB();
    unsigned char beingDebugged = peb[2];
    unsigned int ntGlobalFlag = *(unsigned int*)(peb + 0xBC);
    unsigned int heapFlags = 0;
    unsigned char* heap = *(unsigned char**)(peb + 0x30);
    if(heap)
        heapFlags = *(unsigned int*)(heap + 0x70);
    const char* out = argc > 1 ? argv[1] : "probe_result.txt";
    FILE* f = fopen(out, "w");
    if(!f)
        return 2;
    fprintf(f, "BeingDebugged=%u\nNtGlobalFlag=0x%x\nHeapFlags=0x%x\n",
            beingDebugged, ntGlobalFlag, heapFlags);
    fclose(f);
    return 0;
}
