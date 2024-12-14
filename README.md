# Security-ADMX

Custom ADMX template focused on hardening Windows 10 and Windows 11 systems.

## Available policies

### System policies

#### Enable Virtualization-Based Security in Mandatory mode

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy will enable the Virtualization-Based Security (VBS) function in Mandatory mode.

    Mandatory mode is a new functionnality introduced to prevent the Windows Downdate attack (and other related dowgrading attacks) by forcing the verification of the components of the Secure Kernel and the hypervisor at boot time. Consequently, enabling this functionnality can lead to boot failure (and a denial of service) in case of a modification of a core component of Secure Kernel, hypervisor or a related dependant module.

    NOTE: if you already have Virtualization-Based Security enabled with UEFI Lock, this setting will not do anything, as the VBS configuration is already written and locked in a UEFI variable. This variable needs to be deleted using the bcdedit.exe tool before deploying the Mandatory flag and the UEFI Lock. Guidance and more information about this procedure are available here:

    <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=reg#disable-virtualization-based-security>

    Enabling this policy will set the Mandatory flag and force the verification of the VBS components at boot time.

    Enabling this policy with UEFI Lock already enabled wil do nothing.

    Disabling this policy will disable the verification of the components, only if the UEFI Lock is not enabled. Otherwise, disabling this policy will do nothing.

#### Enable Generative AI features in Acrobat and Acrobat Reader

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** The generative AI features in Acrobat and Acrobat Reader are turned on by default. This policy controls the state of the feature.

    Enabling this policy will enable the Generative AI feature.

    Disabling this policy will disable the Generative AI feature. For privacy purposes, it is recommended to set this policy to Disabled.

#### Configure the Windows Sudo command behavior

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy configures the behavior of the Sudo command introduced in Windows 11 24H2.

    Possible choices are:

    - Force a new elevated window to open (default behavior)
    - Disable inputs to the elevated process
    - Run in the current window
    - Disable the functionnality

    It is recommended to use the default behavior and let the Sudo command open a new elevated window.

#### Enable Secure Boot/Code Integrity mitigations for BlackLotus (CVE-2023-24932)

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy sets the Registry keys needed to apply the updated Secure Boot denylist (DBX), the new signing certificate in the allowlist (DB), the anti-rollback mecanisme (SVN) and the Code Integrity Boot Policy, to prevent untrusted/vulnerable Windows boot managers from loading when Secure Boot is turned on.

    IMPORTANT: carefully read the Microsoft documentation associated with this protection, as it can render your device unable to boot if you do not follow the pre-required steps:

    - <https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d>
    - <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932>

    In particular, you should read all the steps descriptions present in the list and the associated manual operations you need to perform (reboots, additional checks, ...) for each of them in the section of the documentation:

    - <https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_mitigation_guidelines>

#### Prevent standard users to install root certificates

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy prevent standard (non-administrators) users to install root certificate authorities to their user-specific trust store.

    Enabling this policy can help prevent code signing certificate cloning attacks. It is recommended to enable this policy.

#### Block drivers co-installers applications

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** A co-installer is a user-mode Win32 DLL that typically writes additional configuration information to the registry, or performs other installation tasks that require information that is not available when an INF is written.

    If you enable this setting, co-installers execution will be prevented, and additional configuration software for specific devices (mouses, gaming keyboards, etc) must be downloaded and manually installed from the manufacturer website.

    If you disable this setting, co-installers execution will be permitted, which is a significant security risk (potentially dangerous code execution).

#### Limits print driver installation to Administrators

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Determines whether users that aren't Administrator can install print drivers on this computer.

    By default, users that aren't Administrators can't install print drivers on this computer.

    If you enable this setting or do not configure it, the system will limit installation of print drivers to Administrators of this computer.

    If you disable this setting, the system will not limit installation of print drivers to this computer.

    Additional information: <https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7>

#### Enable the strict Authenticode signature verification mechanism

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** The strict Authenticode signature verification mechanism disallow to add extraneous information in the WIN_CERTIFICATE structure.

#### Disable standard users in Safe-Boot mode

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** An adversary with standard user credentials that can boot into Microsoft Windows using Safe Mode, Safe Mode with Networking or Safe Mode with Command Prompt options may be able to bypass system protections and security functionalities. To reduce this risk, users with standard credentials should be prevented from using Safe Mode options to log in.

    Enabling this policy will prevent standard users to open a session in Safe Mode.

    Disabling this policy will allow standard users to open a session in Safe Mode.

#### Enable additional LSA process hardening

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enable this option to allow the LSA process to run as a PPL (Protected Process Light), in order to disallow its debugging.

#### Disable the SAM server TCP listener

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** By default, the SAM server (lsass.exe) is constantly listening on a random TCP port, bound to all network interfaces.

    Enabling this policy will disable the TCP listener.

#### Enable PowerShell Constrained Language Mode

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enable the Constrained Language Mode for Powershell. This mode disallow several language elements that can be leveraged by attackers to perform sensitive APIs calls.

    NOTE: since this policy is only rewritting the __PSLockdownPolicy environment variable, this is not a secure way to enable CLM, and this is intended for defense-in-depth only. CLM can only be securely enforced by AppLocker and/or WDAC.

#### Allow custom DLL loading list for application processes

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** The list is located in the registry key HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WindowsAppInit_DLLs

#### Number of PBKDF2 iterations for cached logons credentials hashing

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** For domains logons, if credentials caching is enabled, credentials are stored as MSCacheV2 hashes, derived using the PBKDF2-SHA1 hashing algorithm.

    The number of iterations for the PBKDF2-SHA1 algorithm used for hashing operations can be controlled with this policy, with the following logic:

    - For a value lower than or equal to 10240, the setting acts as a 1024-mutiplier (for example, setting it to 20 will result in 20480 iterations).
    - For a value greater than 10240, the setting acts as the chosen value (modulo 1024).

    The recommended value depends on the target environment, the CPU power available and the performance hit you are willing to tolerate at logon (a high value can incur a net performance penalty for the logon process).

    When the policy is enabled, the default value configured is 1954 (2 000 896 rounds). This is the recommended value (at the time of December 2022) for the PBKDF2-HMAC-SHA1 algorithm, considering the compute power of a RTX 4090 GPU in a offline bruteforce attack model.

    More information:
    - <https://tobtu.com/minimum-password-settings/>
    - <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2>

#### Disable administrative shares for workstations

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Not recommended, except for highly secure environments.

#### Disable administrative shares for servers

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Not recommended, except for highly secure environments.

#### Enable Spectre and Meltdown mitigations

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** TODO

#### Enable Structured Exception Handling Overwrite Protection (SEHOP)

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** SEHOP blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.

This policy is only effective on 32 bits systems.

#### Enable Network Level Authentication (NLA) for RDP connections

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy enable Network Level Authentication for RDP connections, with the following settings:

    - TLS is required for server authentication and link encryption.
    - High level of encryption (128 bits) for the data link.
    - User authentication is required at connection time.

    Disabling this policy does nothing.

#### Harden network logons and authentication security

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enable this policy to disable LM and NTLM authentication modes, and enable use of NTLMv2 only.

Disable this policy to restore LM and NTLMv1 capabilities, in addition to NTLMv2.

#### Disable WDigest protocol

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enabling this policy will disable the WDigest protocol, now considered obsolete.

    Keeping WDigest enabled could allow an attacker to retrieve plain-text passwords stored in the LSA service with a tool such as Mimikatz, and it is therefore recommended to enable this policy.

#### Domain credentials caching hardening

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enabling this policy modifiy two settings related to how the local system handles domain-related credentials:

    - Reduce the caching count (2 cached credentials) of domain-related credentials for offline authentication if no domain controller is available
    - The delay before the credentials are cleared from memory after a logoff is set to 30 seconds.

    Those settings reduce the exposure time of credentials to attack tools such as Mimikatz.

    NOTE: those settings can prevent a new session opening, if the network is not available, or if a domain controler is not reachable.

#### Force the randomization of relocatable images (ASLR)

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enabling this policy will enable ASLR even for relocatable images that do not explicitly expose this capability.

    Disabling this policy will explicitly disable the ASLR mechanism.

#### Additional registry fix for CVE-2015-6161

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enable this policy to change the registry value FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING to 1.

    This modification is necessary to fully fix an ASLR bypass vulnerability (CVE-2015-6161). For more information, refer to the MS15-124 security bulletin (<https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-124>).

#### Additional registry fix for CVE-2017-8529

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** Enable this policy to change the registry value FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX to 1.

    This modification is necessary to fully fix an information disclosure vulnerability in Microsoft browsers (CVE-2017-8529). For more information, refer to the related security update guide (<https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8529>).

#### Enable kernel-level shadow stacks

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** The policy enable kernel-level shadow stacks, also known as Intel CET (Control-flow Enforcement Technology) or AMD Shadow Stack.

    Please note that this security function require specific hardware support (AMD Zen 3 or Intel 11th Gen. processors) and OS support (Windows 21H2 or newer).

#### Disable the WPBT functionnality

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy disable the Windows Platform Binary Table (WPBT) functionnality, that can be used for persistence through an UEFI implant.

#### Disable Time-Travel Debugging

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy disable the Time-Travel Debugging (TTD) functionnality, that can be used to dump sensitive processes memory content, and to launch third-party executables.

#### Remove current working directory from DLL search

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** The CWDIllegalInDllSearch registry entry is used to remove the current working directory (CWD) from the DLL search order.

#### Enable Windows Defender sandbox

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:** This policy enables the sandbox (content process) for the main process of Windows Defender.

    The new content processes, which run with low privileges, aggressively leverage all available mitigation policies to reduce the attack surface. They enable and prevent runtime changes for modern exploit mitigation techniques such as Data Execution Prevention (DEP), Address space layout randomization (ASLR), and Control Flow Guard (CFG). They also disable Win32K system calls and all extensibility points, as well as enforce that only signed and trusted code is loaded.

    More information: <https://www.microsoft.com/en-us/security/blog/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/>

### Network policies

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

#### POLICY TITLE

- **Registry path(s):**
- **Registry key(s):**
- **Values:**
- **Description:**

### Debugging policies

## Credits

- The Schannel configuration part is taken almost as-is from the [Crosse/SchannelGroupPolicy](https://github.com/Crosse/SchannelGroupPolicy) repository, a big kudo to him for his work :)
- The legacy MSS and the settings from the Microsoft Security Guide arte imported from the Microsoft Security Compliance Toolkit as-is
  - More information: https://www.microsoft.com/en-us/download/details.aspx?id=55319
