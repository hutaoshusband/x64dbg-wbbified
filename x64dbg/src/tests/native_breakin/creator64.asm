EXTERN FixtureGetProcAddress:PROC
EXTERN FixtureVirtualFreeEx:PROC
.data
PUBLIC __imp_GetProcAddress
__imp_GetProcAddress QWORD OFFSET FixtureGetProcAddress
PUBLIC __imp_VirtualFreeEx
__imp_VirtualFreeEx QWORD OFFSET FixtureVirtualFreeEx
END
