using System.Management;
using System.Security.Cryptography;
using System.Text;
using System;
using System.IO;
using System.Security;
using System.Linq;

namespace ComputerUniqueIdentifier
{
    /// <summary>
    /// based on this comment: http://stackoverflow.com/a/16284893
    /// </summary>
    public class ComputerFingerPrintCalculator
    {
        [Flags]
        public enum FingerPrintProviders
        {
            VideoCardDriver = 1,
            FirstProcessorInfo = 2,
            BiosInfo = 4,
            DiskInfo = 8,
            FirstNicMac = 16,
            BaseBoardInfo = 32,
            All = VideoCardDriver | FirstNicMac | FirstProcessorInfo | BiosInfo | DiskInfo | BaseBoardInfo
        }

        public string Compute(FingerPrintProviders providerFlags = FingerPrintProviders.All)
        {
            var rawData = "";
            if (providerFlags.HasFlag(FingerPrintProviders.FirstProcessorInfo))
            {
                rawData += GenerateCpuFingerprint();
            }
            if (providerFlags.HasFlag(FingerPrintProviders.BiosInfo))
            {
                rawData += GenerateBiosFingerprint();
            }
            if (providerFlags.HasFlag(FingerPrintProviders.BaseBoardInfo))
            {
                rawData += GenerateBaseBoardFingerprint();
            }
            if (providerFlags.HasFlag(FingerPrintProviders.DiskInfo))
            {
                rawData += GenerateSystemDiskFingerprint();
            }
            if (providerFlags.HasFlag(FingerPrintProviders.VideoCardDriver))
            {
                rawData += GenerateVideoControllerFingerprint();
            }
            if (providerFlags.HasFlag(FingerPrintProviders.FirstNicMac))
            {
                rawData += GenerateMacAddressFingerprint();
            }
            if (string.IsNullOrEmpty(rawData))
            {
                throw new InvalidOperationException("No fingerprint provider was specified or couldn't retreive data from the computer!");
            }
            return ButifyHexString(GetHash(rawData));
        }

        public string ComputeWithSalt(string salt)
        {
            return ButifyHexString(GetHash(Compute() + salt));
        }

        private string ButifyHexString(string hexStr, int delimitAfter = 5, string delimiter = "-")
        {
            return string.Concat(
                hexStr
                .Replace("-", "")
                .Select((chr, chrIdx) =>
                    ((chrIdx % delimitAfter == 0 && chrIdx != 0) ? delimiter : "")
                    + chr));
        }

        private static string GetHash(string str)
        {
            var stringBytes = Encoding.Default.GetBytes(str);
            var computedHash = new SHA1CryptoServiceProvider().ComputeHash(stringBytes);
            return BitConverter.ToString(computedHash);
        }
        
        private static string QueryWmi(string wmiClass, string wmiProperty, Func<ManagementBaseObject, bool> filter)
        {
            ManagementClass mc = new ManagementClass(wmiClass);
            ManagementObjectCollection moc = mc.GetInstances();
            foreach (ManagementObject mo in moc)
            {
                if (filter(mo))
                {
                    try
                    {
                        return mo[wmiProperty].ToString();
                    }
                    catch
                    {
                    }
                }
            }
            return string.Empty;
        }

        //Return a hardware identifier
        private static string QueryWmi(string wmiClass, string wmiProperty)
        {
            return QueryWmi(wmiClass, wmiProperty, x => true);
        }

        private static string GenerateCpuFingerprint()
        {
            //Uses first CPU identifier available in order of preference
            //Don't get all identifiers, as it is very time consuming
            string retVal = QueryWmi("Win32_Processor", "UniqueId");
            if (retVal == "") //If no UniqueID, use ProcessorID
            {
                retVal = QueryWmi("Win32_Processor", "ProcessorId");
                if (retVal == "") //If no ProcessorId, use Name
                {
                    retVal = QueryWmi("Win32_Processor", "Name");
                    if (retVal == "") //If no Name, use Manufacturer
                    {
                        retVal = QueryWmi("Win32_Processor", "Manufacturer");
                    }
                    //Add clock speed for extra security
                    retVal += QueryWmi("Win32_Processor", "MaxClockSpeed");
                }
            }
            return GetHash(retVal);
        }
        
        private static string GenerateBiosFingerprint()
        {
            return GetHash(QueryWmi("Win32_BIOS", "Manufacturer")
            + QueryWmi("Win32_BIOS", "SMBIOSBIOSVersion")
            + QueryWmi("Win32_BIOS", "IdentificationCode")
            + QueryWmi("Win32_BIOS", "SerialNumber")
            + QueryWmi("Win32_BIOS", "ReleaseDate")
            + QueryWmi("Win32_BIOS", "Version"));
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

        private static string GenerateBaseBoardFingerprint()
        {
            return GetHash(QueryWmi("Win32_BaseBoard", "Model")
            + QueryWmi("Win32_BaseBoard", "Manufacturer")
            + QueryWmi("Win32_BaseBoard", "Name")
            + QueryWmi("Win32_BaseBoard", "SerialNumber"));
        }

        private static string GenerateVideoControllerFingerprint()
        {
            return GetHash(QueryWmi("Win32_VideoController", "DriverVersion")
            + QueryWmi("Win32_VideoController", "Name"));
        }

        private static string GenerateMacAddressFingerprint()
        {
            return GetHash(QueryWmi("Win32_NetworkAdapterConfiguration",
                "MACAddress", mo => mo["IPEnabled"].ToString() == "True"));
        }        
    }
}