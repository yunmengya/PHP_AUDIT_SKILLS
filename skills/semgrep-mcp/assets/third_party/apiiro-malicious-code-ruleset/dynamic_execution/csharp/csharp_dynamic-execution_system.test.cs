using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;
using System;
using System.Reflection;
using System.Diagnostics;


System.Diagnostics.Process.Start("dotnet", "script -e ...");

var process = new System.Diagnostics.Process();
process.StartInfo.FileName = "dotnet";
process.StartInfo.Arguments = "script '...'";
process.Start();

class Program
{
    static void Main()
    {
        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = "script -e \"Console.WriteLine(1 + 2 + 3);\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = Process.Start(psi))
        {
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            System.Console.WriteLine(output);
        }
    }
}