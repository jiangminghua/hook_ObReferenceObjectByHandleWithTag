// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"
#include "common.h"
#include "global_object.h"
#include "hotplug_callback.h"
#include "log.h"
#include "power_callback.h"
#include "util.h"
#include "vm.h"
#include "performance.h"
#include "../../DdiMon/ddi_mon.h"
#include <intrin.h>

extern "C" {


DRIVER_INITIALIZE DriverEntry;

static DRIVER_UNLOAD DriverpDriverUnload;

_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//
extern unsigned int msrarrary[0x1000];
VOID MySystemThread(PVOID StartContext)
{
  //ULONG64 sdfgfhgfg = *(ULONG64*)DbgkDebugObjectType + 0x40 + 0x1c;
  while (TRUE) {    
    LARGE_INTEGER interval = { 0 };
    interval.QuadPart = -(10000ll * 9000);
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    for (size_t i = 0; i < 0x1000; i++)
    {
      if (msrarrary[i] != 0) {
        DbgPrintEx(101, 0, "msrarrary=%d,%x\n",i, msrarrary[i]);
      }
    }
  }
}

void BypassCheckSign(PDRIVER_OBJECT pDriverObj)
{
  //STRUCT FOR WIN64
  typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
  {
    struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
    struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
    struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
    VOID*        DllBase;
    VOID*        EntryPoint;
    ULONG32      SizeOfImage;
    UINT8        _PADDING0_[0x4];
    struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
    struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
    ULONG32      Flags;
  }LDR_DATA, *PLDR_DATA;
  PLDR_DATA ldr;
  ldr = (PLDR_DATA)(pDriverObj->DriverSection);
  ldr->Flags |= 0x20;
}

extern "C" NTKERNELAPI
UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);
extern "C" PEPROCESS GameProcessEPROCESS = 0;

VOID MyCreateProcessNotifyEx(__inout   PEPROCESS Process, __in      HANDLE ProcessId, __in_opt  PPS_CREATE_NOTIFY_INFO CreateInfo)
{
  NTSTATUS st = 0;
  HANDLE hProcess = NULL;
  OBJECT_ATTRIBUTES oa = { 0 };
  CLIENT_ID ClientId = { 0 };
  char xxx[30] = { 0 };
  
  if (CreateInfo != NULL)	//进程创建事件
  {
    memset(xxx, 0, 30);
    memcpy(xxx, PsGetProcessImageFileName(Process), 16);
    //DbgPrintEx(101, 0, "[%ld]%s创建进程: %wZ\n", CreateInfo->ParentProcessId, GetProcessNameByProcessId(CreateInfo->ParentProcessId), CreateInfo->ImageFileName);
    if ((strstr(xxx, "x32dbg.exe")) || (strstr(xxx, "cheatengine-x86_64.exe")))
    {
      //DbgPrintEx(101, 0, "[%ld]%s创建进程: %wZ\n", CreateInfo->ParentProcessId, GetProcessNameByProcessId(CreateInfo->ParentProcessId), CreateInfo->ImageFileName);
      //CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;	//禁止创建进程
      //x32dbgProcessId = ProcessId;
      //debuggerCR3 = *((ULONG64*)Process + 0x28 / 8);//_KPROCESS +0x028 DirectoryTableBase
      //DbgPrintEx(101, 0, "debuggerCR3=%p\n", debuggerCR3);
    }
    if (memcmp(xxx, "League of L",strlen("League of L"))==0)
    {
      GameProcessEPROCESS = Process;
      DbgPrintEx(101, 0, "GameProcessEPROCESS=%p,%llx\n", GameProcessEPROCESS, *(ULONG64*)GameProcessEPROCESS);
    }
    //else
      //DbgPrintEx(101, 0, "%ld,create Process EPROCESS=%p,%wZ,%s\n", CreateInfo->ParentProcessId, Process, CreateInfo->ImageFileName,xxx);
  }
  else
  {
    memcpy(xxx, PsGetProcessImageFileName(Process), 16);
    if (memcmp(xxx, "League of L", strlen("League of L")) == 0)
    {
      GameProcessEPROCESS = 0;
      DbgPrintEx(101, 0, "process exit: %s\n", PsGetProcessImageFileName(Process));
    }
    
  }
}


// A driver entry point
_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                            PUNICODE_STRING registry_path) {
  UNREFERENCED_PARAMETER(registry_path);
  PAGED_CODE();
 
  static const wchar_t kLogFilePath[] = L"\\SystemRoot\\DdiMon.log";
  static const auto kLogLevel =
      (IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
                         : kLogPutLevelDebug | kLogOptDisableFunctionName;
  RtlZeroMemory(msrarrary, sizeof(msrarrary));
  HANDLE systemHandle;

  //PsCreateSystemThread(&systemHandle, GENERIC_ALL, 0, 0, 0, MySystemThread, 0);
  //UINT64 cr0 = __readcr0();
  //cr0 &= 0xfffffffffffeffff;
  //__writecr0(cr0);

  //*(char*)ObRegisterCallbacks = 0xc3;
  //CHAR XORRAXRAXRET[4] = { 0x33, 0xc0, 0xc3 };//XOR rax,rax  ret
  //CHAR XORRAXRAXRET1[7] = { 0xb8,0x0d,0,0,0xc0,0xc3 };//mov     eax,0C000000Dh ret 
  //memcpy(PsSetCreateProcessNotifyRoutineEx, XORRAXRAXRET, 3);
  //memcpy(PsSetCreateProcessNotifyRoutine, XORRAXRAXRET, 3);
  //memcpy(PsSetCreateThreadNotifyRoutine, XORRAXRAXRET, 3);
  //memcpy(PsSetLoadImageNotifyRoutine, XORRAXRAXRET, 3);



  //cr0 = __readcr0();
  //cr0 |= 0x10000;
  //__writecr0(cr0);
  //return 0;
  BypassCheckSign(driver_object);
  auto status = STATUS_UNSUCCESSFUL;
  driver_object->DriverUnload = DriverpDriverUnload;
  //HYPERPLATFORM_COMMON_DBG_BREAK();

  // Request NX Non-Paged Pool when available
  ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

  // Initialize log functions
  bool need_reinitialization = false;
  status = LogInitialization(kLogLevel, kLogFilePath);
  if (status == STATUS_REINITIALIZATION_NEEDED) {
    need_reinitialization = true;
  } else if (!NT_SUCCESS(status)) {
    return status;
  }

  // Test if the system is supported
  if (!DriverpIsSuppoetedOS()) {
    LogTermination();
    return STATUS_CANCELLED;
  }

  // Initialize global variables
  status = GlobalObjectInitialization();
  if (!NT_SUCCESS(status)) {
    LogTermination();
    return status;
  }

  // Initialize perf functions
  status = PerfInitialization();
  if (!NT_SUCCESS(status)) {
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize utility functions
  status = UtilInitialization(driver_object);
  if (!NT_SUCCESS(status)) {
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize power callback
  status = PowerCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Initialize hot-plug callback
  status = HotplugCallbackInitialization();
  if (!NT_SUCCESS(status)) {
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Virtualize all processors
  status = VmInitialization();
  if (!NT_SUCCESS(status)) {
    HotplugCallbackTermination();
    PowerCallbackTermination();
    UtilTermination();
    PerfTermination();
    GlobalObjectTermination();
    LogTermination();
    return status;
  }

  // Register re-initialization for the log functions if needed
  if (need_reinitialization) {
    LogRegisterReinitialization(driver_object);
  }

  PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)MyCreateProcessNotifyEx, FALSE);
  HYPERPLATFORM_LOG_INFO("20210802The VMM has been installed.");

  /*UINT64 cr0 = __readcr0();
  cr0 &= 0xfffffffffffeffff;
  __writecr0(cr0);
  *(char*)ObRegisterCallbacks = 0xc3;
  cr0 = __readcr0();
  cr0 |= 0x10000;
  __writecr0(cr0);*/
  
  return status;
}

// Unload handler
_Use_decl_annotations_ static void DriverpDriverUnload(
    PDRIVER_OBJECT driver_object) {
  UNREFERENCED_PARAMETER(driver_object);
  PAGED_CODE();

  HYPERPLATFORM_COMMON_DBG_BREAK();

  VmTermination();
  HotplugCallbackTermination();
  PowerCallbackTermination();
  UtilTermination();
  PerfTermination();
  GlobalObjectTermination();
  LogTermination();
}

// Test if the system is one of supported OS versions
_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
  PAGED_CODE();

  RTL_OSVERSIONINFOW os_version = {};
  auto status = RtlGetVersion(&os_version);
  if (!NT_SUCCESS(status)) {
    return false;
  }
  if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
    return false;
  }
  // 4-gigabyte tuning (4GT) should not be enabled
  if (!IsX64() &&
      reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
    return false;
  }
  return true;
}

}  // extern "C"
