#<include stdio.h>
#<include wdm.h>

NTSTATUS ZwUnmapViewOfSection(
  _In_     HANDLE ProcessHandle,
  _In_opt_ PVOID  BaseAddress
);

main
