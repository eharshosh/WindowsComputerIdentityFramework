using System;
using System.Diagnostics;

namespace WindowsComputerIdentityFramework
{
    class Program
    {
        const string HardCodedSalt = "3t67gh#$z56A";
        static void Main(string[] args)
        {
            var sw = new Stopwatch();
            sw.Start();
            var c = new ComputerFingerPrintCalculator();
            var idHash = c.Compute();
            var salted = c.ComputeWithSalt(HardCodedSalt);
            Console.WriteLine("Raw:\t" + idHash);
            Console.WriteLine($"Salted:\t" + salted);
            Console.WriteLine(sw.Elapsed);
            Console.Read();
        }

        
    }
}
