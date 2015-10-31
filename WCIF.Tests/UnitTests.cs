using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WindowsComputerIdentityFramework;

namespace WCIF.Tests
{
    [TestClass]
    public class UnitTests
    {
        const string HardCodedSalt = "3t67gh#$z56A";
        const string AnotherHardCodedSalt = "1t67gh#$z56A";

        [TestMethod]
        public void TestEndToEnd()
        {
            var c = new ComputerFingerPrintCalculator();
            var idHash = c.Compute();
            var salted = c.ComputeWithSalt(HardCodedSalt);
            var idHash2 = c.Compute();
            var salted2 = c.ComputeWithSalt(HardCodedSalt);
            Assert.AreEqual(idHash, idHash2);
            Assert.AreEqual(salted, salted2);
            Assert.AreNotEqual(idHash, salted);
            Console.WriteLine("Computed (raw):");
            Console.WriteLine(idHash);
            Console.WriteLine("Salted:");
            Console.WriteLine(salted);
        }

        [TestMethod]
        public void TestCompute()
        {
            var c = new ComputerFingerPrintCalculator();
            var idHash = c.Compute();
            Console.WriteLine(idHash);
        }

        [TestMethod]
        public void TestComputeWithSalt()
        {
            var c = new ComputerFingerPrintCalculator();
            var salted = c.ComputeWithSalt(HardCodedSalt);
            Console.WriteLine(salted);
        }

        [TestMethod]
        public void TestDifferentSalts()
        {
            var c = new ComputerFingerPrintCalculator();
            var notSalted = c.Compute();
            var salted = c.ComputeWithSalt(HardCodedSalt);           
            var salted2 = c.Saltify(notSalted, HardCodedSalt);
            Assert.AreNotEqual(notSalted, salted);
            Assert.AreEqual(salted, salted2);
            var saltedUsingAnotherSalt = c.Saltify(notSalted, AnotherHardCodedSalt);
            Assert.AreNotEqual(salted2, saltedUsingAnotherSalt);
            Console.WriteLine("Salted with {0}:\t{1}", HardCodedSalt, salted);
            Console.WriteLine("Salted with {0}:\t{1}", AnotherHardCodedSalt, saltedUsingAnotherSalt);
        }
    }
}
