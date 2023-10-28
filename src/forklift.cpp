#include "silver/fork.h"

#include <windows.h>
#include <processthreadsapi.h>
#include <setjmp.h>
#include <errno.h>
#include <atomic>

#define INTERACTIVE 0

#include "dbg.h"
#if INTERACTIVE
#include <stdio.h>
#endif

// https://learn.microsoft.com/en-us/windows/win32/api/_proc_snap/
/* #include "processsnapshot.h" */ // not available in MinGW

// see also: https://github.com/dahall/Vanara/blob/master/PInvoke/Kernel32/ProcessSnapshot.cs (apidoc)

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ne-processsnapshot-pss_capture_flags
typedef enum {
    PSS_CAPTURE_NONE = 0x00000000,
    PSS_CAPTURE_VA_CLONE = 0x00000001,
    PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
    PSS_CAPTURE_HANDLES = 0x00000004,
    PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
    PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
    PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
    PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
    PSS_CAPTURE_THREADS = 0x00000080,
    PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
    PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
    PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
    PSS_CAPTURE_VA_SPACE = 0x00000800,
    PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
    PSS_CAPTURE_IPT_TRACE = 0x00002000,
    PSS_CAPTURE_RESERVED_00004000,
    PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
    PSS_CREATE_BREAKAWAY = 0x08000000,
    PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
    PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
    PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
    PSS_CREATE_RELEASE_SECTION = 0x80000000
} PSS_CAPTURE_FLAGS;

typedef HANDLE HPSS; // inferences

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ne-processsnapshot-pss_query_information_class
typedef enum {
    PSS_QUERY_PROCESS_INFORMATION = 0,
    PSS_QUERY_VA_CLONE_INFORMATION = 1,
    PSS_QUERY_AUXILIARY_PAGES_INFORMATION = 2,
    PSS_QUERY_VA_SPACE_INFORMATION = 3,
    PSS_QUERY_HANDLE_INFORMATION = 4,
    PSS_QUERY_THREAD_INFORMATION = 5,
    PSS_QUERY_HANDLE_TRACE_INFORMATION = 6,
    PSS_QUERY_PERFORMANCE_COUNTERS = 7
  } PSS_QUERY_INFORMATION_CLASS;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ns-processsnapshot-pss_va_clone_information
typedef struct {
    HANDLE VaCloneHandle;
} PSS_VA_CLONE_INFORMATION;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ns-processsnapshot-pss_thread_information
typedef struct {
    DWORD ThreadsCaptured;
    DWORD ContextLength;
} PSS_THREAD_INFORMATION;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ns-processsnapshot-pss_allocator
typedef struct {
    void *Context;
    void (*AllocRoutine)(void* Context, DWORD Size);
    void (*FreeRoutine)(void* Context, void* Address);
} PSS_ALLOCATOR;

typedef HANDLE HPSSWALK;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ne-processsnapshot-pss_walk_information_class
typedef enum {
  PSS_WALK_AUXILIARY_PAGES = 0,
  PSS_WALK_VA_SPACE = 1,
  PSS_WALK_HANDLES = 2,
  PSS_WALK_THREADS = 3
} PSS_WALK_INFORMATION_CLASS;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ne-processsnapshot-pss_process_flags
typedef enum {
    PSS_PROCESS_FLAGS_NONE = 0x00000000,
    PSS_PROCESS_FLAGS_PROTECTED = 0x00000001,
    PSS_PROCESS_FLAGS_WOW64 = 0x00000002,
    PSS_PROCESS_FLAGS_RESERVED_03 = 0x00000004,
    PSS_PROCESS_FLAGS_RESERVED_04 = 0x00000008,
    PSS_PROCESS_FLAGS_FROZEN = 0x00000010
} PSS_PROCESS_FLAGS;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ns-processsnapshot-pss_process_information
typedef struct {
    DWORD             ExitStatus;
    void              *PebBaseAddress;
    ULONG_PTR         AffinityMask;
    LONG              BasePriority;
    DWORD             ProcessId;
    DWORD             ParentProcessId;
    PSS_PROCESS_FLAGS Flags;
    FILETIME          CreateTime;
    FILETIME          ExitTime;
    FILETIME          KernelTime;
    FILETIME          UserTime;
    DWORD             PriorityClass;
    ULONG_PTR         PeakVirtualSize;
    ULONG_PTR         VirtualSize;
    DWORD             PageFaultCount;
    ULONG_PTR         PeakWorkingSetSize;
    ULONG_PTR         WorkingSetSize;
    ULONG_PTR         QuotaPeakPagedPoolUsage;
    ULONG_PTR         QuotaPagedPoolUsage;
    ULONG_PTR         QuotaPeakNonPagedPoolUsage;
    ULONG_PTR         QuotaNonPagedPoolUsage;
    ULONG_PTR         PagefileUsage;
    ULONG_PTR         PeakPagefileUsage;
    ULONG_PTR         PrivateUsage;
    DWORD             ExecuteFlags;
    wchar_t           ImageFileName[MAX_PATH];
} PSS_PROCESS_INFORMATION;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ne-processsnapshot-pss_thread_flags
typedef enum {
    PSS_THREAD_FLAGS_NONE = 0x0000,
    PSS_THREAD_FLAGS_TERMINATED = 0x0001
} PSS_THREAD_FLAGS;

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ns-processsnapshot-pss_thread_entry
typedef struct {
    DWORD            ExitStatus;
    void             *TebBaseAddress;
    DWORD            ProcessId;
    DWORD            ThreadId;
    ULONG_PTR        AffinityMask;
    int              Priority;
    int              BasePriority;
    void             *LastSyscallFirstArgument;
    WORD             LastSyscallNumber;
    FILETIME         CreateTime;
    FILETIME         ExitTime;
    FILETIME         KernelTime;
    FILETIME         UserTime;
    void             *Win32StartAddress;
    FILETIME         CaptureTime;
    PSS_THREAD_FLAGS Flags;
    WORD             SuspendCount;
    WORD             SizeOfContextRecord;
    PCONTEXT         ContextRecord;
} PSS_THREAD_ENTRY;

extern "C" {

#define WINPSSAPI __attribute((weak)) __declspec(dllimport)

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot
WINPSSAPI DWORD PssCaptureSnapshot(HANDLE ProcessHandle, PSS_CAPTURE_FLAGS CaptureFlags, DWORD ThreadContextFlags, HPSS *SnapshotHandle);

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-pssquerysnapshot
WINPSSAPI DWORD PssQuerySnapshot(HPSS SnapshotHandle, PSS_QUERY_INFORMATION_CLASS InformationClass, void *Buffer, DWORD BufferLength);

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-pssfreesnapshot
WINPSSAPI DWORD PssFreeSnapshot(HANDLE ProcessHandle, HPSS SnapshotHandle);

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psswalkmarkercreate
WINPSSAPI DWORD PssWalkMarkerCreate(PSS_ALLOCATOR const *Allocator, HPSSWALK *WalkMarkerHandle);

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psswalksnapshot
WINPSSAPI DWORD PssWalkSnapshot(HPSS SnapshotHandle, PSS_WALK_INFORMATION_CLASS InformationClass, HPSSWALK WalkMarkerHandle, void* Buffer, DWORD BufferLength);

// https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psswalkmarkerfree
WINPSSAPI DWORD PssWalkMarkerFree(HPSSWALK WalkMarkerHandle);

WINPSSAPI NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

// https://www.codeproject.com/questions/369890/ask-about-ntcreatethreadex-in-window-7-x64
DWORD WINAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, DWORD, DWORD, DWORD, LPVOID);

// NTSYSCALLAPI NTSTATUS NTAPI ZwCreateProcessEx	(	_Out_ PHANDLE 	ProcessHandle,
// _In_ ACCESS_MASK 	DesiredAccess,
// _In_opt_ POBJECT_ATTRIBUTES 	ObjectAttributes,
// _In_ HANDLE 	ParentProcess,
// _In_ ULONG 	Flags,
// _In_opt_ HANDLE 	SectionHandle,
// _In_opt_ HANDLE 	DebugPort,
// _In_opt_ HANDLE 	ExceptionPort,
// _In_ ULONG 	JobMemberLevel 
// )

// https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ms686736(v=vs.85)
static DWORD WINAPI pickup(LPVOID lpParameter) {
    jmp_buf* ama_ghi = (jmp_buf*) lpParameter;
    longjmp(*ama_ghi, 1);
}

#define nuance(retcode) (errno = (ERROR_ACCESS_DENIED == retcode) ? EPERM : ENOSYS)

HPSS CaptureProcess(HANDLE process) {
    HPSS snapshot;
    PSS_CAPTURE_FLAGS flags = (PSS_CAPTURE_FLAGS)(PSS_CAPTURE_VA_CLONE|PSS_CAPTURE_THREADS|PSS_CAPTURE_VA_SPACE|PSS_CREATE_USE_VM_ALLOCATIONS);
    DWORD retcode = PssCaptureSnapshot(process, flags, 0, &snapshot);
    if(ERROR_SUCCESS != retcode) {
        _SILVER_LOG("PssCaptureSnapshot=%lu LastError=%lu", retcode, GetLastError());
        return errno = ENOMEM, INVALID_HANDLE_VALUE;
    }

    return snapshot;
}

HANDLE AnalyzeSnapshot(HPSS snapshot) {
    PSS_VA_CLONE_INFORMATION clone;
    DWORD retcode = PssQuerySnapshot(snapshot, PSS_QUERY_VA_CLONE_INFORMATION, &clone, sizeof(clone));
    if(ERROR_SUCCESS != retcode) {
        _SILVER_LOG("PssQuerySnapshot(clone)=%lu LastError=%lu", retcode, GetLastError());
        PssFreeSnapshot(GetCurrentProcess(), snapshot);
        return nuance(retcode), INVALID_HANDLE_VALUE;
    }

    PSS_PROCESS_INFORMATION proc;
    retcode = PssQuerySnapshot(snapshot, PSS_QUERY_PROCESS_INFORMATION, &proc, sizeof(proc));
    if(ERROR_SUCCESS != retcode) {
        _SILVER_LOG("PssQuerySnapshot(proc)=%lu LastError=%lu", retcode, GetLastError());
    } else {
        _SILVER_LOG("remote: pid=%lu ppid=%lu flags=0x%x", proc.ProcessId, proc.ParentProcessId, proc.Flags);
        // 0x4 is PSS_PROCESS_FLAGS_RESERVED_03 -- STATUS_PROCESS_IS_TERMINATING
    }

    PSS_THREAD_INFORMATION threads;
    retcode = PssQuerySnapshot(snapshot, PSS_QUERY_THREAD_INFORMATION, &threads, sizeof(threads));
    if(ERROR_SUCCESS != retcode) { // e.g. 1168=ERROR_NOT_FOUND
        _SILVER_LOG("PssQuerySnapshot(threads)=%lu LastError=%lu", retcode, GetLastError());
    } else {
        HPSSWALK cursor = NULL;
        PssWalkMarkerCreate(NULL /* allocator */, &cursor);
        PSS_THREAD_ENTRY thread;
        // iterate until ERROR_NO_MORE_ITEMS
        while(ERROR_SUCCESS == PssWalkSnapshot(snapshot, PSS_WALK_THREADS, cursor, &thread, sizeof(thread))) {
            _SILVER_LOG("remote thread: pid=%lu tid=%lu suspends=%u exited=%d(%d)",
                    thread.ProcessId, thread.ThreadId, thread.SuspendCount, thread.ExitStatus, (STILL_ACTIVE != thread.ExitStatus));
        }
        PssWalkMarkerFree(cursor);
    }

    const pid_t child = GetProcessId(clone.VaCloneHandle);
    HANDLE child_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, child); // MOREINFO replace w/ clone.VaCloneHandle?
    return child_proc; // or, again, clone.VaCloneHandle
}

pid_t fork() {
    if(!(&PssCaptureSnapshot && &PssQuerySnapshot)) {
        _SILVER_LOG("PssCaptureSnapshot=%p PssQuerySnapshot=%p", &PssCaptureSnapshot, &PssQuerySnapshot);
        return errno = ENOTSUP, -1; // no PSS API
    }

    BOOLEAN b;
    RtlAdjustPrivilege(20/* SE_DEBUG_PRIVILEGE */, TRUE, FALSE, &b);

    // "Ama-ghi" means "back to mom" (the Sumerian expression for "freedom";
    // literally "back home", as genealogy and inheritance were matrilineal)
    jmp_buf ama_ghi;
    if(setjmp(ama_ghi)) {
        return 0; // success
    } else {
        std::atomic_thread_fence(std::memory_order_seq_cst); // flush data cache
        // MOREINFO: is FlushProcessWriteBuffers() exact equivalent to the above?
    }

    _SILVER_LOG("self: pid=%lu tid=%lu", GetCurrentProcessId(), GetCurrentThreadId());

    HPSS snapshot = CaptureProcess(GetCurrentProcess());
    HANDLE child_proc = AnalyzeSnapshot(snapshot);
    HPSS secondary = CaptureProcess(child_proc);
    HANDLE grandchild = AnalyzeSnapshot(secondary);

    pid_t child = GetProcessId(child_proc); // FIXME return both from AnalyzeSnapshot!

#if INTERACTIVE
    getc(stdin); // re-#include <stdio.h> if reenabled
#endif

    SYSTEM_INFO si;
    GetSystemInfo(&si); // get VM page size
    // now pick up the saved thread context
    if(CreateRemoteThread(child_proc, NULL, 0 /* page size */, &pickup, &ama_ghi, 0 /* no flags */, NULL /* no tid */)) {
        // we don't need the returned thread handle, as the thread will never complete and will forever remain in zombie state
        // PssFreeSnapshot?
        CloseHandle(child_proc);
        return child;
    } else {
        DWORD retcode = GetLastError();
        _SILVER_LOG("CreateRemoteThread(%p) in %d: LastError=%lu", child_proc, child, retcode);
        HANDLE child_thread = NULL;
        retcode = NtCreateThreadEx(&child_thread, GENERIC_EXECUTE, NULL, child_proc, &pickup, &ama_ghi, FALSE, NULL, NULL, NULL, NULL);
        if(ERROR_SUCCESS != retcode) {
            _SILVER_LOG("NtCreateThreadEx(%p) in %d: %p, LastError=0x%lx", child_proc, child, child_thread, retcode);
        }
        PssFreeSnapshot(GetCurrentProcess(), snapshot);
        return nuance(retcode), -1;
    }
} // that's all forks!

} // extern "C"
