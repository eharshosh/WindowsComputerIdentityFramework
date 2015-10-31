using System;

namespace WindowsComputerIdentityFramework
{
    [Flags]
    public enum FingerPrintProviders
    {
        VideoCardDriver = 1,
        Processor = 2,
        Bios = 4,
        SystemDisk = 8,
        FirstEnabledNicMac = 16,
        BaseBoard = 32,
        All = VideoCardDriver | FirstEnabledNicMac | Processor | Bios | SystemDisk | BaseBoard
    }
}
