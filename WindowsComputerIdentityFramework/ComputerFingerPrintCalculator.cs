using System.Management;
using System.Security.Cryptography;
using System.Text;
using System;
using System.IO;
using System.Security;
using System.Linq;
using System.Collections.Generic;

namespace WindowsComputerIdentityFramework
{
    /// <summary>
    /// based on this comment: http://stackoverflow.com/a/16284893
    /// </summary>
    public class ComputerFingerPrintCalculator
    {
        public string Compute(FingerPrintProviders providerFlags = FingerPrintProviders.All)
        {
            var rawData = "";
            if ((providerFlags | FingerPrintProviders.Processor) == providerFlags)
            {
                rawData += GenerateCpuFingerprint();
            }
            if ((providerFlags | FingerPrintProviders.Bios) == providerFlags)
            {
                rawData += GenerateBiosFingerprint();
            }
            if ((providerFlags | FingerPrintProviders.BaseBoard) == providerFlags)
            {
                rawData += GenerateBaseBoardFingerprint();
            }
            if ((providerFlags | FingerPrintProviders.SystemDisk) == providerFlags)
            {
                rawData += GenerateSystemDiskFingerprint();
            }
            if ((providerFlags | FingerPrintProviders.VideoCardDriver) == providerFlags)
            {
                rawData += GenerateVideoControllerFingerprint();
            }
            if ((providerFlags | FingerPrintProviders.FirstEnabledNicMac) == providerFlags)
            {
                rawData += GenerateMacAddressFingerprint();
            }
            if (string.IsNullOrEmpty(rawData))
            {
                throw new SecurityException("No fingerprint provider was specified or couldn't retreive data from the computer!");
            }
            return ButifyHexString(GetHash(rawData));
        }

        public string ComputeWithSalt(string salt)
        {
            return ButifyHexString(GetHash(Compute() + salt));
        }

        private string ButifyHexString(string hexStr, int delimitAfter = 5, string delimiter = "-")
        {
            return string.Join("",
                hexStr
                .Replace("-", "")
                .Select((chr, chrIdx) =>
                    ((chrIdx % delimitAfter == 0 && chrIdx != 0) ? delimiter : "")
                    + chr).ToArray());
        }

        private static string GetHash(string str)
        {
            var stringBytes = Encoding.Default.GetBytes(str);
            var computedHash = new SHA1CryptoServiceProvider().ComputeHash(stringBytes);
            return BitConverter.ToString(computedHash);
        }

        private static IEnumerable<string> QueryWmi(string wmiClass, params string[] wmiProperties)
        {
            ManagementClass mc = new ManagementClass(wmiClass);
            ManagementObjectCollection moc = mc.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                foreach (var propertyName in wmiProperties)
                {
                    var value = mo[propertyName];
                    if (value != null)
                    {
                        yield return value.ToString();
                    }
                }
                yield break;
            }
        }

        private static string GenerateCpuFingerprint()
        {
            var queryResult = QueryWmi("Win32_Processor", "UniqueId",
                "ProcessorId", "Name", "Manufacturer", "MaxClockSpeed");
            return GetHash(string.Join("", queryResult.ToArray()));
        }

        private static string GenerateBiosFingerprint()
        {
            var queryResult = QueryWmi("Win32_BIOS",
                "Manufacturer",
                "SMBIOSBIOSVersion",
                "IdentificationCode",
                "SerialNumber",
                "ReleaseDate",
                "Version");
            return GetHash(string.Join("", queryResult.ToArray()));
        }

        private static string GenerateBaseBoardFingerprint()
        {
            var queryResult = QueryWmi("Win32_BaseBoard", "Model", "Manufacturer", "Name", "SerialNumber");
            return GetHash(string.Join("", queryResult.ToArray()));
        }

        private static string GenerateVideoControllerFingerprint()
        {
            var queryResult = QueryWmi("Win32_VideoController", "DriverVersion", "Name");
            return GetHash(string.Join("", queryResult.ToArray()));
        }

        private static string GenerateMacAddressFingerprint()
        {
            ManagementClass mc = new ManagementClass("Win32_NetworkAdapterConfiguration");
            ManagementObjectCollection moc = mc.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                if (mo["IPEnabled"].ToString() == "True")
                {
                    var macAddress = mo["MACAddress"];
                    if (macAddress != null)
                    {
                        return GetHash(macAddress.ToString());
                    }
                }
            }
            throw new SecurityException("No active network adapters detected!");
        }

        private static string GenerateSystemDiskFingerprint()
        {
            string systemDriveName = Path.GetPathRoot(Environment.SystemDirectory);
            ManagementClass mc = new ManagementClass("Win32_DiskDrive");
            ManagementObjectCollection diskDrives = mc.GetInstances();
            foreach (ManagementObject diskDrive in diskDrives)
            {
                var diskDriveId = diskDrive["DeviceID"].ToString().Replace("\\", "\\\\"); // forward slah is a reserved character in WMI... (need to escape it)
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "ASSOCIATORS OF {Win32_DiskDrive.DeviceID=\"" + diskDriveId + "\"} " +
                    "WHERE AssocClass = Win32_DiskDriveToDiskPartition");
                var partitions = searcher.Get();
                foreach (ManagementObject partition in partitions)
                {
                    searcher = new ManagementObjectSearcher(
                    "ASSOCIATORS OF {Win32_DiskPartition.DeviceID=\"" + partition["DeviceID"] + "\"} " +
                    "WHERE AssocClass = Win32_LogicalDiskToPartition");
                    var logicalDisks = searcher.Get();
                    foreach (ManagementObject logicalDisk in logicalDisks)
                    {
                        var logicalDiskName = logicalDisk["DeviceID"].ToString() + "\\";
                        if (logicalDiskName == systemDriveName)
                        {
                            var result = diskDrive["SerialNumber"].ToString().Trim();
                            if (string.IsNullOrEmpty(result))
                            {
                                throw new SecurityException("Could not retreive the serial number of the OS disk!");
                            }
                            return GetHash(result);
                        }
                    }
                }
            }
            throw new SecurityException("The OS disk was not found!");
        }
    }
}