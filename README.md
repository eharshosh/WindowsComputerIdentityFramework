# WindowsComputerIdentityFramework

### This project aims to provide a globally unique computer identifier for Windows-running computer.
The identifier should change even if the disk of the computer has cloned to another computer.

The algorithm computes the identifier of the computer and generates an SHA-1 hash string, representing the hashed combination of the following parameters of the computer:

* Video-Card driver
 * Driver Version
 * Driver Name
* Processor
 * UniqueId  (if applicable, might not be unique at all - see https://msdn.microsoft.com/en-us/library/aa394373(v=vs.85).aspx )
 * ProcessorId
 * Name
 * Manufacturer
 * MaxClockSpeed
* Bios
 * Manufacturer
 * SMBIOSBIOSVersion
 * IdentificationCode
 * SerialNumber
 * ReleaseDate
 * Version
* System Disk Serial Number
* First Enabled NIC MAC Address
* BaseBoard
 * Model
 * Manufacturer
 * Name
 * SerialNumber

