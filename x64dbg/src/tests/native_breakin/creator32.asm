.386
.model flat
EXTERN _FixtureGetProcAddress@8:PROC
EXTERN _FixtureVirtualFreeEx@16:PROC
.data
PUBLIC __imp__GetProcAddress@8
__imp__GetProcAddress@8 DWORD OFFSET _FixtureGetProcAddress@8
PUBLIC __imp__VirtualFreeEx@16
__imp__VirtualFreeEx@16 DWORD OFFSET _FixtureVirtualFreeEx@16
END
