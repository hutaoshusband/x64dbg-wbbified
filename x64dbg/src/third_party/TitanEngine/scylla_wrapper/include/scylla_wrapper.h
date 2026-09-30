/*
*
* Copyright (c) 2014
*
* cypher <the.cypher@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//packing set to 1 needed because TitanEngine uses same
#pragma pack(push, 1)

typedef enum
{
    SCY_ERROR_SUCCESS = 0,
    SCY_ERROR_PROCOPEN = -1,
    SCY_ERROR_IATWRITE = -2,
    SCY_ERROR_IATSEARCH = -3,
    SCY_ERROR_IATNOTFOUND = -4
} ScyllaErrorCode;;

typedef struct
{
    bool NewDll;
    int NumberOfImports;
    ULONG_PTR ImageBase;
    ULONG_PTR BaseImportThunk;
    ULONG_PTR ImportThunk;
    char* APIName;
    char* DLLName;
} ScyllaImportEnumData, *PScyllaImportEnumData;

//IAT exports
int scylla_searchIAT(DWORD pid, DWORD_PTR & iatStart, DWORD & iatSize, DWORD_PTR searchStart, bool advancedSearch);
int scylla_getImports(DWORD_PTR iatAddr, DWORD iatSize, DWORD pid, LPVOID invalidImportCallback = NULL);
bool scylla_addModule(const WCHAR* moduleName, DWORD_PTR firstThunkRVA);
bool scylla_addImport(const WCHAR* importName, DWORD_PTR thunkVA);
bool scylla_importsValid();
bool scylla_cutImport(DWORD_PTR apiAddr);
int scylla_fixDump(const WCHAR* dumpFile, const WCHAR* iatFixFile, const WCHAR* sectionName = L".scy");
int scylla_fixMappedDump(DWORD_PTR iatVA, DWORD_PTR FileMapVA, HANDLE hFileMap);
int scylla_getModuleCount();
int scylla_getImportCount();
void scylla_enumImportTree(LPVOID enumCallBack);
long scylla_estimatedIATSize();
DWORD_PTR scylla_findImportWriteLocation(const char* importName);
DWORD_PTR scylla_findOrdinalImportWriteLocation(DWORD_PTR ordinalNumber);
DWORD_PTR scylla_findImportNameByWriteLocation(DWORD_PTR thunkVA);
DWORD_PTR scylla_findModuleNameByWriteLocation(DWORD_PTR thunkVA);

//dumper exports
bool scylla_dumpProcessW(DWORD_PTR pid, const WCHAR* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR* fileResult);
bool scylla_dumpProcessA(DWORD_PTR pid, const char* fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char* fileResult);

//rebuilder exports
bool scylla_rebuildFileW(const WCHAR* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);
bool scylla_rebuildFileA(const char* fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup);

#pragma pack(pop)