param(
    [string]$SourceImage = "C:\Windows\System32\cmd.exe",
    [string]$TargetImage = "C:\Windows\System32\notepad.exe"
)

$ErrorActionPreference = "Stop"

Write-Host "Event 25 dangerous helper" -ForegroundColor Yellow
Write-Host "Source image : $SourceImage"
Write-Host "Target image : $TargetImage"
Write-Host ""

if (-not (Test-Path $SourceImage)) {
    throw "Source image not found: $SourceImage"
}
if (-not (Test-Path $TargetImage)) {
    throw "Target image not found: $TargetImage"
}

$signature = @"
using System;
using System.IO;
using System.Runtime.InteropServices;

public static class Event25Tamper
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public UInt32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public UInt32 dwX;
        public UInt32 dwY;
        public UInt32 dwXSize;
        public UInt32 dwYSize;
        public UInt32 dwXCountChars;
        public UInt32 dwYCountChars;
        public UInt32 dwFillAttribute;
        public UInt32 dwFlags;
        public UInt16 wShowWindow;
        public UInt16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public UInt32 dwProcessId;
        public UInt32 dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        UInt32 dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("ntdll.dll")]
    static extern Int32 NtQueryInformationProcess(
        IntPtr ProcessHandle,
        Int32 ProcessInformationClass,
        ref PROCESS_BASIC_INFORMATION ProcessInformation,
        UInt32 ProcessInformationLength,
        out UInt32 ReturnLength
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern UInt32 ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr hProcess, UInt32 uExitCode);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr hObject);

    public static void Invoke(string sourceImage, string targetImage)
    {
        byte[] sourceBytes = File.ReadAllBytes(sourceImage);
        if (sourceBytes.Length < 64)
        {
            throw new InvalidOperationException("Source image is too small.");
        }

        STARTUPINFO si = new STARTUPINFO();
        si.cb = (UInt32)Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION pi;

        const UInt32 CREATE_SUSPENDED = 0x00000004;
        bool ok = CreateProcess(targetImage, null, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
        if (!ok)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess failed");
        }

        try
        {
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            UInt32 returnLength;
            Int32 ntStatus = NtQueryInformationProcess(pi.hProcess, 0, ref pbi, (UInt32)Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)), out returnLength);
            if (ntStatus != 0)
            {
                throw new InvalidOperationException("NtQueryInformationProcess failed with status 0x" + ntStatus.ToString("X"));
            }

            IntPtr pebImageBasePointer = IntPtr.Add(pbi.PebBaseAddress, 0x10);
            byte[] imageBaseBuffer = new byte[IntPtr.Size];
            IntPtr bytesRead;
            if (!ReadProcessMemory(pi.hProcess, pebImageBasePointer, imageBaseBuffer, imageBaseBuffer.Length, out bytesRead))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory for PEB image base failed");
            }

            long imageBase = IntPtr.Size == 8
                ? BitConverter.ToInt64(imageBaseBuffer, 0)
                : BitConverter.ToUInt32(imageBaseBuffer, 0);

            byte[] headers = new byte[0x1000];
            if (!ReadProcessMemory(pi.hProcess, new IntPtr(imageBase), headers, headers.Length, out bytesRead))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "ReadProcessMemory for PE headers failed");
            }

            int e_lfanew = BitConverter.ToInt32(headers, 0x3C);
            int optionalHeaderOffset = e_lfanew + 0x18;
            int addressOfEntryPoint = BitConverter.ToInt32(headers, optionalHeaderOffset + 0x10);
            IntPtr entryPointAddress = new IntPtr(imageBase + addressOfEntryPoint);

            byte[] tamperBytes = new byte[64];
            Array.Copy(sourceBytes, 0, tamperBytes, 0, tamperBytes.Length);

            IntPtr bytesWritten;
            if (!WriteProcessMemory(pi.hProcess, entryPointAddress, tamperBytes, tamperBytes.Length, out bytesWritten))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory failed");
            }

            ResumeThread(pi.hThread);
            System.Threading.Thread.Sleep(1500);
            TerminateProcess(pi.hProcess, 0);
        }
        finally
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}
"@

Add-Type -TypeDefinition $signature -Language CSharp
[Event25Tamper]::Invoke($SourceImage, $TargetImage)
Write-Host ""
Write-Host "Event 25 helper completed. Review Sysmon Event ID 25 around this execution window." -ForegroundColor Green
