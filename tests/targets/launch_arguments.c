#include <windows.h>
#include <stdio.h>

static void write_text(FILE* stream, const char* name, const wchar_t* value)
{
    fprintf(stream, "%s=", name);
    for(const wchar_t* character = value; *character; ++character)
        fprintf(stream, "%02x%02x", *character & 255, (*character >> 8) & 255);
    fputc('\n', stream);
}

int wmain(int argc, wchar_t* argv[])
{
    FILE* stream = fopen("launch_arguments_result.txt", "w");
    if(!stream)
        return 2;
    fprintf(stream, "argc=%d\n", argc);
    for(int index = 0; index < argc; ++index)
    {
        char name[32];
        sprintf_s(name, sizeof(name), "argv%d", index);
        write_text(stream, name, argv[index]);
    }
    wchar_t directory[32768];
    if(!GetCurrentDirectoryW(sizeof(directory) / sizeof(directory[0]), directory))
    {
        fclose(stream);
        return 3;
    }
    write_text(stream, "cwd", directory);
    write_text(stream, "rawCommandLine", GetCommandLineW());
    fclose(stream);
    return 17;
}
