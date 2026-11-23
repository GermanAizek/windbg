# windbg

windbg (windbg.sys / hpsafe.sys / CopperStealth Rootkit Driver) - kernel mode rootkit driver analyzed in the CopperStealth malware campaigns by TrendMicro, used for process injection, kernel code manipulation, and file system filter interception.

My opensource driver does not use the original source codes and is a reverse-engineered driver using [Ghidra](https://en.wikipedia.org/wiki/Ghidra) and [Radare2](https://en.wikipedia.org/wiki/Radare2). The rights have not been violated, and the new driver cannot be signed due to the EV certificate. I hope that the vulnerabilities can be closed using my security patches.

The main goal of the project is to recreate a secure driver with neutralized rootkit capabilities and fixed vulnerabilities.

### Functions

Driver windbg.sys was designed to provide stealthy kernel and user-mode execution controls:

- Remote user-mode process memory allocation and entry point JMP (0xE9) hooking (IOCTL 0x00222000)
- Kernel code and non-paged pool memory modification via MDL mapping (IOCTL 0x00222004)
- File system registration change monitoring and filter attachment (IoRegisterFsRegistrationChange)
- Selective IOCTL interception and process blocking (IOCTL 0x00222008, 0x0022200C)

Fixed vulnerabilities in opensource driver windbg.sys:

- [x] [LOLDrivers: windbg.sys](https://www.loldrivers.io/drivers/da7314dc-6cf1-4d74-a0d1-796fc08944f8/)
  - Low-privilege users can inject code into system processes (explorer.exe), overwrite kernel memory, intercept file systems, and execute arbitrary code in kernel mode (BYOVD, MITRE ATT&CK T1068). Fixed by enforcing administrative ACLs on device creation, neutralizing process injection, restricting MDL kernel memory writes, and validating filesystem filter attachments.

Fixed no publish vulnerabilities and bugs which contributors to this project found:

- [x] Device deletion bypassed on symbolic link deletion failure ([view code](main.c))
- [x] Arbitrary user-mode process code injection and execution in command 0x00222000 ([view code](inject.c))
- [x] Arbitrary kernel code and read-only memory overwrite via MDL in command 0x00222004 ([view code](patch.c))
- [x] Unauthorized file system filter device attachment and leak on unload ([view code](fsfilter.c))
- [x] Unauthorized process blocking and IOCTL denial of service in command 0x00222008 ([view code](main.c))
- [x] Device creation with weak permissions ([view code](main.c))

Authors:

- 2026 - Herman Semenoff <<GermanAizek@yandex.ru>> ([germanaizek.github.io](https://germanaizek.github.io))
- TrendMicro Threat Research <<threat_research@trendmicro.com>>
