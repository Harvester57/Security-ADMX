# Security-ADMX

Custom ADMX template focused on hardening Windows 10 and Windows 11 systems.

## Release status

[![Linting](https://github.com/Harvester57/Security-ADMX/actions/workflows/linting.yml/badge.svg)](https://github.com/Harvester57/Security-ADMX/actions/workflows/linting.yml)
[![Latest release](https://img.shields.io/github/v/release/Harvester57/Security-ADMX)](https://github.com/Harvester57/Security-ADMX/releases)

## Table of contents

- [System policies](#system-policies)
  - [Enable Virtualization-Based Security in Mandatory mode](#enable-virtualization-based-security-in-mandatory-mode)
  - [Enable Generative AI features in Acrobat and Acrobat Reader](#enable-generative-ai-features-in-acrobat-and-acrobat-reader)
  - [Configure the Windows Sudo command behavior](#configure-the-windows-sudo-command-behavior)
  - [Enable Secure Boot/Code Integrity mitigations for BlackLotus (CVE-2023-24932)](#enable-secure-bootcode-integrity-mitigations-for-blacklotus-cve-2023-24932)
  - [Prevent standard users to install root certificates](#prevent-standard-users-to-install-root-certificates)
  - [Block drivers co-installers applications](#block-drivers-co-installers-applications)
  - [Limits print driver installation to Administrators](#limits-print-driver-installation-to-administrators)
  - [Enable the strict Authenticode signature verification mechanism](#enable-the-strict-authenticode-signature-verification-mechanism)
  - [Enable AMSI Authenticode signature verification](#enable-amsi-authenticode-signature-verification)
  - [Disable standard users in Safe-Boot mode](#disable-standard-users-in-safe-boot-mode)
  - [Enable additional LSA process hardening](#enable-additional-lsa-process-hardening)
  - [Disable the SAM server TCP listener](#disable-the-sam-server-tcp-listener)
  - [Enable PowerShell Constrained Language Mode](#enable-powershell-constrained-language-mode)
  - [Allow custom DLL loading list for application processes](#allow-custom-dll-loading-list-for-application-processes)
  - [Number of PBKDF2 iterations for cached logons credentials hashing](#number-of-pbkdf2-iterations-for-cached-logons-credentials-hashing)
  - [Disable administrative shares for workstations](#disable-administrative-shares-for-workstations)
  - [Disable administrative shares for servers](#disable-administrative-shares-for-servers)
  - [Enable Spectre and Meltdown mitigations](#enable-spectre-and-meltdown-mitigations)
  - [Enable Structured Exception Handling Overwrite Protection (SEHOP)](#enable-structured-exception-handling-overwrite-protection-sehop)
  - [Enable Network Level Authentication (NLA) for RDP connections](#enable-network-level-authentication-nla-for-rdp-connections)
  - [Harden network logons and authentication security](#harden-network-logons-and-authentication-security)
  - [Disable WDigest protocol](#disable-wdigest-protocol)
  - [Domain credentials caching hardening](#domain-credentials-caching-hardening)
  - [Force the randomization of relocatable images (ASLR)](#force-the-randomization-of-relocatable-images-aslr)
  - [Additional registry fix for CVE-2015-6161](#additional-registry-fix-for-cve-2015-6161)
  - [Additional registry fix for CVE-2017-8529](#additional-registry-fix-for-cve-2017-8529)
  - [Enable kernel-level shadow stacks](#enable-kernel-level-shadow-stacks)
  - [Disable the WPBT functionnality](#disable-the-wpbt-functionnality)
  - [Disable Time-Travel Debugging](#disable-time-travel-debugging)
  - [Remove current working directory from DLL search](#remove-current-working-directory-from-dll-search)
  - [Enable Windows Defender sandbox](#enable-windows-defender-sandbox)
  - [Block remote DCOM connections](#block-remote-dcom-connections)
  - [Block credential stealing from the Windows local security authority subsystem (lsass.exe)](#block-credential-stealing-from-the-windows-local-security-authority-subsystem-lsassexe)
  - [Block abuse of exploited vulnerable signed drivers](#block-abuse-of-exploited-vulnerable-signed-drivers)
  - [Block Adobe Reader from creating child processes](#block-adobe-reader-from-creating-child-processes)
  - [Block all Office applications from creating child processes](#block-all-office-applications-from-creating-child-processes)
  - [Block executable content from email client and webmail](#block-executable-content-from-email-client-and-webmail)
  - [Block executable files from running unless they meet a prevalence, age, or trusted list criterion](#block-executable-files-from-running-unless-they-meet-a-prevalence-age-or-trusted-list-criterion)
  - [Block execution of potentially obfuscated scripts](#block-execution-of-potentially-obfuscated-scripts)
  - [Block JavaScript or VBScript from launching downloaded executable content](#block-javascript-or-vbscript-from-launching-downloaded-executable-content)
  - [Block Office applications from creating executable content](#block-office-applications-from-creating-executable-content)
  - [Block Office applications from injecting code into other processes](#block-office-applications-from-injecting-code-into-other-processes)
  - [Block Office communication application from creating child processes](#block-office-communication-application-from-creating-child-processes)
  - [Block persistence through WMI event subscription](#block-persistence-through-wmi-event-subscription)
  - [Block process creations originating from PSExec and WMI commands](#block-process-creations-originating-from-psexec-and-wmi-commands)
  - [Block rebooting machine in Safe Mode (preview)](#block-rebooting-machine-in-safe-mode-preview)
  - [Block untrusted and unsigned processes that run from USB](#block-untrusted-and-unsigned-processes-that-run-from-usb)
  - [Block use of copied or impersonated system tools (preview)](#block-use-of-copied-or-impersonated-system-tools-preview)
  - [Block Webshell creation for Servers](#block-webshell-creation-for-servers)
  - [Block Win32 API calls from Office macros](#block-win32-api-calls-from-office-macros)
  - [Use advanced protection against ransomware](#use-advanced-protection-against-ransomware)
  - [Block execution of files related to Remote Monitoring and Management tools](#block-execution-of-files-related-to-remote-monitoring-and-management-tools)
  - [Apply UAC restrictions to local accounts on network logons](#apply-uac-restrictions-to-local-accounts-on-network-logons)
  - [Lsass.exe audit mode](#lsassexe-audit-mode)
  - [Remove "Run As Different User" from context menus](#remove-run-as-different-user-from-context-menus)
  - [Configure SMBv1 server](#configure-smbv1-server)
  - [Configure SMBv1 client driver](#configure-smbv1-client-driver)
  - [NetBT NodeType configuration](#netbt-nodetype-configuration)
  - [Block Flash activation in Office documents](#block-flash-activation-in-office-documents)
  - [Restrict legacy JScript execution for Office](#restrict-legacy-jscript-execution-for-office)
  - [Configure RPC packet level privacy setting for incoming connections](#configure-rpc-packet-level-privacy-setting-for-incoming-connections)
  - [MSS: (AutoReboot) Configure automatic system restart after a crash](#mss-autoreboot-configure-automatic-system-restart-after-a-crash)
  - [MSS: (AutoAdminLogon) Configure Automatic Logon](#mss-autoadminlogon-configure-automatic-logon)
  - [MSS: (DisableSavePassword) Prevent the dial-up password from being saved](#mss-disablesavepassword-prevent-the-dial-up-password-from-being-saved)
  - [MSS: (EnableDeadGWDetect) Configure dead gateway detection](#mss-enabledeadgwdetect-configure-dead-gateway-detection)
  - [MSS: (EnableICMPRedirect) Allow ICMP redirects](#mss-enableicmpredirect-allow-icmp-redirects)
  - [MSS: (Hidden) Hide computer from network browse lists](#mss-hidden-hide-computer-from-network-browse-lists)
  - [MSS: (KeepAliveTime) Configure TCP keep-alive interval](#mss-keepalivetime-configure-tcp-keep-alive-interval)
  - [MSS: (NoDefaultExempt) Configure IPSec traffic exemptions](#mss-nodefaultexempt-configure-ipsec-traffic-exemptions)
  - [MSS: (NoNameReleaseOnDemand) Ignore NetBIOS name release requests](#mss-nonamereleaseondemand-ignore-netbios-name-release-requests)
  - [MSS: (NtfsDisable8dot3NameCreation) Configure 8.3 short name creation for NTFS](#mss-ntfsdisable8dot3namecreation-configure-83-short-name-creation-for-ntfs)
  - [MSS: (PerformRouterDiscovery) Configure ICMP Router Discovery (IRDP)](#mss-performrouterdiscovery-configure-icmp-router-discovery-irdp)
  - [MSS: (SafeDllSearchMode) Configure Safe DLL search mode](#mss-safedllsearchmode-configure-safe-dll-search-mode)
  - [MSS: (ScreenSaverGracePeriod) Configure screen saver grace period](#mss-screensavergraceperiod-configure-screen-saver-grace-period)
  - [MSS: (SynAttackProtect) Configure TCP SYN attack protection](#mss-synattackprotect-configure-tcp-syn-attack-protection)
  - [MSS: (TcpMaxConnectResponseRetransmissions) Configure number of SYN-ACK retransmissions](#mss-tcpmaxconnectresponseretransmissions-configure-number-of-syn-ack-retransmissions)
  - [MSS: (TcpMaxDataRetransmissions) Configure max TCP data retransmissions (IPv4)](#mss-tcpmaxdataretransmissions-configure-max-tcp-data-retransmissions-ipv4)
  - [MSS: (TcpMaxDataRetransmissions IPv6) Configure max TCP data retransmissions (IPv6)](#mss-tcpmaxdataretransmissions-ipv6-configure-max-tcp-data-retransmissions-ipv6)
  - [MSS: (WarningLevel) Configure security event log full warning level](#mss-warninglevel-configure-security-event-log-full-warning-level)
- [Network policies](#network-policies)
  - [TLS cipher suites configuration](#tls-cipher-suites-configuration)
  - [Configure the IP source routing protection level](#configure-the-ip-source-routing-protection-level)
  - [Configure the IP source routing protection level for IPv6](#configure-the-ip-source-routing-protection-level-for-ipv6)
  - [Enable Kerberos events logging](#enable-kerberos-events-logging)
  - [Disable SMB 1.0 support (client and server)](#disable-smb-10-support-client-and-server)
  - [Configure the minimum SMB2/3 client dialect supported](#configure-the-minimum-smb23-client-dialect-supported)
  - [Configure the maximum SMB2/3 client dialect supported](#configure-the-maximum-smb23-client-dialect-supported)
  - [Enable support for TLS 1.2 only in WinHTTP](#enable-support-for-tls-12-only-in-winhttp)
  - [Enable advanced logging for Schannel](#enable-advanced-logging-for-schannel)
  - [Disable the strong-name bypass feature](#disable-the-strong-name-bypass-feature)
  - [.NET Framework 4: enable strong cryptographic support](#net-framework-4-enable-strong-cryptographic-support)
  - [.NET Framework 2: enable strong cryptographic support](#net-framework-2-enable-strong-cryptographic-support)
  - [Multi-Protocol Unified Hello](#multi-protocol-unified-hello)
  - [PCT 1.0](#pct-10)
  - [SSL 2.0](#ssl-20)
  - [SSL 3.0](#ssl-30)
  - [TLS 1.0](#tls-10)
  - [TLS 1.1](#tls-11)
  - [TLS 1.2](#tls-12)
  - [TLS 1.3](#tls-13)
  - [DTLS 1.0](#dtls-10)
  - [DTLS 1.2](#dtls-12)
  - [DTLS 1.3](#dtls-13)
  - [NULL](#null)
  - [DES 56/56](#des-5656)
  - [RC2 40/128](#rc2-40128)
  - [RC2 56/128](#rc2-56128)
  - [RC2 128/128](#rc2-128128)
  - [RC4 40/128](#rc4-40128)
  - [RC4 56/128](#rc4-56128)
  - [RC4 64/128](#rc4-64128)
  - [RC4 128/128](#rc4-128128)
  - [Triple DES 168](#triple-des-168)
  - [AES 128/128](#aes-128128)
  - [AES 256/256](#aes-256256)
  - [MD5](#md5)
  - [SHA](#sha)
  - [SHA-256](#sha-256)
  - [SHA-384](#sha-384)
  - [SHA-512](#sha-512)
  - [Diffie-Hellman](#diffie-hellman)
  - [Diffie-Hellman Server-side Key Size](#diffie-hellman-server-side-key-size)
  - [Diffie-Hellman Client-side Key Size](#diffie-hellman-client-side-key-size)
  - [PKCS](#pkcs)
  - [PKCS Client-side Key Size](#pkcs-client-side-key-size)
  - [ECDH](#ecdh)
- [Debugging policies](#debugging-policies)
  - [Enable Kernel Address Sanitizer](#enable-kernel-address-sanitizer)
  - [Enable detailed Blue Screens of Death (BSOD)](#enable-detailed-blue-screens-of-death-bsod)

## Available policies

### System policies

#### Enable Virtualization-Based Security in Mandatory mode

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\DeviceGuard
- **Registry key(s):** Mandatory
- **Values:** 0/1
- **Description:** This policy will enable the Virtualization-Based Security (VBS) function in Mandatory mode.

    Mandatory mode is a new functionnality introduced to prevent the Windows Downdate attack (and other related dowgrading attacks) by forcing the verification of the components of the Secure Kernel and the hypervisor at boot time. Consequently, enabling this functionnality can lead to boot failure (and a denial of service) in case of a modification of a core component of Secure Kernel, hypervisor or a related dependant module.

    NOTE: if you already have Virtualization-Based Security enabled with UEFI Lock, this setting will not do anything, as the VBS configuration is already written and locked in a UEFI variable. This variable needs to be deleted using the bcdedit.exe tool before deploying the Mandatory flag and the UEFI Lock. Guidance and more information about this procedure are available here:

    <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=reg#disable-virtualization-based-security>

    Enabling this policy will set the Mandatory flag and force the verification of the VBS components at boot time.

    Enabling this policy with UEFI Lock already enabled wil do nothing.

    Disabling this policy will disable the verification of the components, only if the UEFI Lock is not enabled. Otherwise, disabling this policy will do nothing.

#### Enable Generative AI features in Acrobat and Acrobat Reader

- **Registry path(s):** SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown
- **Registry key(s):** bEnableGentech
- **Values:** 0/1
- **Description:** The generative AI features in Acrobat and Acrobat Reader are turned on by default. This policy controls the state of the feature.

    Enabling this policy will enable the Generative AI feature.

    Disabling this policy will disable the Generative AI feature. For privacy purposes, it is recommended to set this policy to Disabled.

#### Configure the Windows Sudo command behavior

- **Registry path(s):** SOFTWARE\Policies\Microsoft\Windows\Sudo
- **Registry key(s):** Enabled
- **Values:** 0/1/2/3
- **Description:** This policy configures the behavior of the Sudo command introduced in Windows 11 24H2.

    Possible choices are:

  - Force a new elevated window to open (default behavior)
  - Disable inputs to the elevated process
  - Run in the current window
  - Disable the functionnality

    It is recommended to use the default behavior and let the Sudo command open a new elevated window.

#### Enable Secure Boot/Code Integrity mitigations for BlackLotus (CVE-2023-24932)

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Secureboot
- **Registry key(s):** AvailableUpdates
- **Values:** 64/256/128/512
- **Description:** This policy sets the Registry keys needed to apply the updated Secure Boot denylist (DBX), the new signing certificate in the allowlist (DB), the anti-rollback mecanisme (SVN) and the Code Integrity Boot Policy, to prevent untrusted/vulnerable Windows boot managers from loading when Secure Boot is turned on.

    IMPORTANT: carefully read the Microsoft documentation associated with this protection, as it can render your device unable to boot if you do not follow the pre-required steps:

  - <https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d>
  - <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932>

    In particular, you should read all the steps descriptions present in the list and the associated manual operations you need to perform (reboots, additional checks, ...) for each of them in the section of the documentation:

  - <https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_mitigation_guidelines>

#### Prevent standard users to install root certificates

- **Registry path(s):** SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots
- **Registry key(s):** Flags
- **Values:** 0/1
- **Description:** This policy prevent standard (non-administrators) users to install root certificate authorities to their user-specific trust store.

    Enabling this policy can help prevent code signing certificate cloning attacks. It is recommended to enable this policy.

#### Block drivers co-installers applications

- **Registry path(s):** SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer
- **Registry key(s):** DisableCoInstallers
- **Values:** 0/1
- **Description:** A co-installer is a user-mode Win32 DLL that typically writes additional configuration information to the registry, or performs other installation tasks that require information that is not available when an INF is written.

    If you enable this setting, co-installers execution will be prevented, and additional configuration software for specific devices (mouses, gaming keyboards, etc) must be downloaded and manually installed from the manufacturer website.

    If you disable this setting, co-installers execution will be permitted, which is a significant security risk (potentially dangerous code execution).

#### Limits print driver installation to Administrators

- **Registry path(s):** Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint
- **Registry key(s):** RestrictDriverInstallationToAdministrators
- **Values:** 0/1
- **Description:** Determines whether users that aren't Administrator can install print drivers on this computer.

    By default, users that aren't Administrators can't install print drivers on this computer.

    If you enable this setting or do not configure it, the system will limit installation of print drivers to Administrators of this computer.

    If you disable this setting, the system will not limit installation of print drivers to this computer.

    Additional information: <https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7>

#### Enable the strict Authenticode signature verification mechanism

- **Registry path(s):**
  - Software\Microsoft\Cryptography\Wintrust\Config
  - Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config
- **Registry key(s):** EnableCertPaddingCheck
- **Values:** 1/`<delete>`
- **Description:** The strict Authenticode signature verification mechanism disallow to add extraneous information in the WIN_CERTIFICATE structure.

#### Enable AMSI Authenticode signature verification

- **Registry path(s):** SOFTWARE\Microsoft\AMSI
- **Registry key(s):** FeatureBits
- **Values:** 2/1
- **Description:** This policy enables the verification of the Authenticode signature of the AMSI provider.

    If you enable this policy, the AMSI provider must be signed by a trusted certificate.

    If you disable or do not configure this policy, the signature verification is disabled (default behavior).

#### Disable standard users in Safe-Boot mode

- **Registry path(s):** SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
- **Registry key(s):** SafeModeBlockNonAdmins
- **Values:** 0/1
- **Description:** An adversary with standard user credentials that can boot into Microsoft Windows using Safe Mode, Safe Mode with Networking or Safe Mode with Command Prompt options may be able to bypass system protections and security functionalities. To reduce this risk, users with standard credentials should be prevented from using Safe Mode options to log in.

    Enabling this policy will prevent standard users to open a session in Safe Mode.

    Disabling this policy will allow standard users to open a session in Safe Mode.

#### Enable additional LSA process hardening

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Lsa
- **Registry key(s):** RunAsPPL
- **Values:** 0/1
- **Description:** Enable this option to allow the LSA process to run as a PPL (Protected Process Light), in order to disallow its debugging.

#### Disable the SAM server TCP listener

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Lsa
- **Registry key(s):** SamDisableListenOnTCP
- **Values:** 0/1
- **Description:** By default, the SAM server (lsass.exe) is constantly listening on a random TCP port, bound to all network interfaces.

    Enabling this policy will disable the TCP listener.

#### Enable PowerShell Constrained Language Mode

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Session Manager\Environment
- **Registry key(s):** __PSLockdownPolicy
- **Values:** 4/0
- **Description:** Enable the Constrained Language Mode for Powershell. This mode disallow several language elements that can be leveraged by attackers to perform sensitive APIs calls.

    NOTE: since this policy is only rewritting the __PSLockdownPolicy environment variable, this is not a secure way to enable CLM, and this is intended for defense-in-depth only. CLM can only be securely enforced by AppLocker and/or WDAC.

#### Allow custom DLL loading list for application processes

- **Registry path(s):** Software\Microsoft\Windows NT\CurrentVersion\Windows
- **Registry key(s):** LoadAppInit_DLLs
- **Values:** 0/1
- **Description:** The list is located in the registry key HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WindowsAppInit_DLLs

#### Number of PBKDF2 iterations for cached logons credentials hashing

- **Registry path(s):** SECURITY\Cache
- **Registry key(s):** NL$IterationCount
- **Values:** 1 to 200000000
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

- **Registry path(s):** SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
- **Registry key(s):** AutoShareWks
- **Values:** 0/1
- **Description:** Not recommended, except for highly secure environments.

#### Disable administrative shares for servers

- **Registry path(s):** SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
- **Registry key(s):** AutoShareServer
- **Values:** 0/1
- **Description:** Not recommended, except for highly secure environments.

#### Enable Spectre and Meltdown mitigations

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
  - SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization
- **Registry key(s):**
  - FeatureSettingsOverride
  - FeatureSettingsOverrideMask
  - MinVmVersionForCpuBasedMitigations
- **Values:**
  - 72/8264/8/0/1/64/3
  - 3
  - 1.0
- **Description:** The FeatureSettingsOverride registry key in Windows, typically found under SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management and often managed alongside FeatureSettingsOverrideMask, provides administrators with granular control over software-based mitigations for CPU speculative execution vulnerabilities like Spectre and Meltdown.

    These vulnerabilities can potentially allow unauthorized access to sensitive data. Windows implements various mitigations to counter these threats, but they can sometimes introduce performance overhead. The FeatureSettingsOverride key allows for a tailored approach, enabling administrators to selectively enable or disable specific mitigations—such as those for different variants of Spectre (like v2 or Speculative Store Bypass - SSB) and Meltdown—or even to disable all of them if the performance impact is deemed too high for a particular environment, or to apply specific configurations like disabling Hyper-Threading on Intel CPUs in conjunction with these mitigations.

    This policy also allows to enable Hyper-V mitigations for virtual machines below version 8.0 (MinVmVersionForCpuBasedMitigations).

    Available options:
  - Intel and AMD: enable all available mitigations
  - Intel: enable all mitigations (with Hyper-Threading disabled)
  - Intel: enable mitigations for Spectre v2, Meltdown, and SSB
  - Intel: enable mitigations for Spectre v2 and Meltdown
  - Intel: enable mitigations for Meltdown only
  - AMD and ARM: enable mitigations for Spectre v2
  - Disable all mitigations

#### Enable Structured Exception Handling Overwrite Protection (SEHOP)

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Session Manager\kernel
- **Registry key(s):** DisableExceptionChainValidation
- **Values:** 0/1
- **Description:** SEHOP blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.

This policy is only effective on 32 bits systems.

#### Enable Network Level Authentication (NLA) for RDP connections

- **Registry path(s):** SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
- **Registry key(s):**
  - SecurityLayer
  - UserAuthentication
  - MinEncryptionLevel
- **Values:**
  - 2
  - 1
  - 3
- **Description:** This policy enable Network Level Authentication for RDP connections, with the following settings:

  - TLS is required for server authentication and link encryption.
  - High level of encryption (128 bits) for the data link.
  - User authentication is required at connection time.

  Disabling this policy does nothing.

#### Harden network logons and authentication security

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Lsa
- **Registry key(s):** LmCompatibilityLevel
- **Values:** 5/1
- **Description:** Enable this policy to disable LM and NTLM authentication modes, and enable use of NTLMv2 only.

Disable this policy to restore LM and NTLMv1 capabilities, in addition to NTLMv2.

#### Disable WDigest protocol

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
- **Registry key(s):**
  - UseLogonCredential
  - Negotiate
- **Values:**
  - 0
  - 0
- **Description:** Enabling this policy will disable the WDigest protocol, now considered obsolete.

    Keeping WDigest enabled could allow an attacker to retrieve plain-text passwords stored in the LSA service with a tool such as Mimikatz, and it is therefore recommended to enable this policy.

#### Domain credentials caching hardening

- **Registry path(s):**
  - SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
  - SYSTEM\CurrentControlSet\Control\Lsa
- **Registry key(s):**
  - CachedLogonsCount
  - TokenLeakDetectDelaySecs
- **Values:**
  - 2
  - 30
- **Description:** Enabling this policy modifiy two settings related to how the local system handles domain-related credentials:

  - Reduce the caching count (2 cached credentials) of domain-related credentials for offline authentication if no domain controller is available
  - The delay before the credentials are cleared from memory after a logoff is set to 30 seconds.

  Those settings reduce the exposure time of credentials to attack tools such as Mimikatz.

  NOTE: those settings can prevent a new session opening, if the network is not available, or if a domain controler is not reachable.

#### Force the randomization of relocatable images (ASLR)

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
- **Registry key(s):** MoveImages
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling this policy will enable ASLR even for relocatable images that do not explicitly expose this capability.

  Disabling this policy will explicitly disable the ASLR mechanism.

#### Additional registry fix for CVE-2015-6161

- **Registry path(s):**
  - SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING
  - SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING
- **Registry key(s):** iexplore.exe
- **Values:** 0/1
- **Description:** Enable this policy to change the registry value FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING to 1.

  This modification is necessary to fully fix an ASLR bypass vulnerability (CVE-2015-6161). For more information, refer to the MS15-124 security bulletin (<https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-124>).

#### Additional registry fix for CVE-2017-8529

- **Registry path(s):**
  - SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX
  - SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX
- **Registry key(s):** iexplore.exe
- **Values:** 0/1
- **Description:** Enable this policy to change the registry value FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX to 1.

    This modification is necessary to fully fix an information disclosure vulnerability in Microsoft browsers (CVE-2017-8529). For more information, refer to the related security update guide (<https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8529>).

#### Enable kernel-level shadow stacks

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks
- **Registry key(s):** Enabled
- **Values:** 0/1
- **Description:** The policy enable kernel-level shadow stacks, also known as Intel CET (Control-flow Enforcement Technology) or AMD Shadow Stack.

    Please note that this security function require specific hardware support (AMD Zen 3 or Intel 11th Gen. processors) and OS support (Windows 21H2 or newer).

#### Disable the WPBT functionnality

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Session Manager
- **Registry key(s):** DisableWpbtExecution
- **Values:** 0/1
- **Description:** This policy disable the Windows Platform Binary Table (WPBT) functionnality, that can be used for persistence through an UEFI implant.

#### Disable Time-Travel Debugging

- **Registry path(s):** SOFTWARE\Microsoft\TTD
- **Registry key(s):** RecordingPolicy
- **Values:** 0/2
- **Description:** This policy disable the Time-Travel Debugging (TTD) functionnality, that can be used to dump sensitive processes memory content, and to launch third-party executables.

#### Remove current working directory from DLL search

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Session Manager
- **Registry key(s):** CWDIllegalInDllSearch
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** The CWDIllegalInDllSearch registry entry is used to remove the current working directory (CWD) from the DLL search order.

#### Enable Windows Defender sandbox

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Session Manager\Environment
- **Registry key(s):** MP_FORCE_USE_SANDBOX
- **Values:** 0/1
- **Description:** This policy enables the sandbox (content process) for the main process of Windows Defender.

    The new content processes, which run with low privileges, aggressively leverage all available mitigation policies to reduce the attack surface. They enable and prevent runtime changes for modern exploit mitigation techniques such as Data Execution Prevention (DEP), Address space layout randomization (ASLR), and Control Flow Guard (CFG). They also disable Win32K system calls and all extensibility points, as well as enforce that only signed and trusted code is loaded.

    More information: <https://www.microsoft.com/en-us/security/blog/2018/10/26/windows-defender-antivirus-can-now-run-in-a-sandbox/>

### Network policies

#### TLS cipher suites configuration

- **Registry path(s):** SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002
- **Registry key(s):** Functions
- **Values:**
  - TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_CCM_SHA256
  - TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_CCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CCM,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CCM,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  - TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256,TLS_AES_128_CCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CCM,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CCM,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
- **Description:** This policy allows you to select between several TLS cipher suites configuration profiles.

    NOTE: for profiles listed with TLS 1.3, please verify that your OS version support TLS 1.3 (Windows 10 v1903 and up) and that TLS 1.3 support is enabled in the Schannel "Protocols" section, otherwise you could break TLS support on your system.

    Changing this setting will require a restart of the computer before the setting will take effect. You can check the applied configuration with the Get-TlsCiphersuite cmdlet in a PowerShell session.

    Ciphers enabled for each profile, in order of preference:

    **Modern (TLS 1.3 only)**

    TLS_AES_256_GCM_SHA384
    TLS_AES_128_GCM_SHA256
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256

    **Modern (TLS 1.3 and 1.2)**

    TLS_AES_256_GCM_SHA384
    TLS_AES_128_GCM_SHA256
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

    **Standard (TLS 1.2 only)**

    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

    **Backward compatible (TLS 1.3, 1.2, 1.1 and 1.0)**
    TLS_AES_256_GCM_SHA384
    TLS_AES_128_GCM_SHA256
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

    **Backward compatible (TLS 1.2, 1.1 and 1.0)**

    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

#### Configure the IP source routing protection level

- **Registry path(s):** System\CurrentControlSet\Services\Tcpip\Parameters
- **Registry key(s):** DisableIPSourceRouting
- **Values:** 0/1/2
- **Description:** Allows to choose a protection for source-routed packets.

#### Configure the IP source routing protection level for IPv6

- **Registry path(s):** System\CurrentControlSet\Services\Tcpip6\Parameters
- **Registry key(s):** DisableIPSourceRouting
- **Values:** 0/1/2
- **Description:** Allows to choose a protection for source-routed packets.

#### Enable Kerberos events logging

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters
- **Registry key(s):** LogLevel
- **Values:** 0/1
- **Description:** Enable logging of debug events related to Kerberos in the System Event log.

    If disabled, this policy disable Kerberos-related events logging (this is the default behavior). Enabling this option is only recommended for debugging purposes. Security auditing of events related to Kerberos events should be configured with Advanced Auditing policies.

#### Disable SMB 1.0 support (client and server)

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
  - SYSTEM\CurrentControlSet\services\mrxsmb10
- **Registry key(s):**
  - SMB1
  - Start
- **Values:**
  - 0
  - 4
- **Description:** Disable SMB 1.0 support (client and server)

#### Configure the minimum SMB2/3 client dialect supported

- **Registry path(s):** SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
- **Registry key(s):** MinSMB2Dialect
- **Values:** 514/528/768/770/785/`<delete>`
- **Description:**This policy allows you to configure the minimum SMB2/3 version supported when acting as a client.

    It is recommended to select the minimal version supported by your environment.

    NOTE: if you select a version above what the remote server can, handle, you will not be able to connect to the remote file share.

    Supported versions:
  - SMB 2.0.2
  - SMB 2.1.0 (Windows 7)
  - SMB 3.0.0 (Windows 8)
  - SMB 3.0.2 (windows 8.1)
  - SMB 3.1.1 (Windows 10, Windows Server 2016)

#### Configure the maximum SMB2/3 client dialect supported

- **Registry path(s):** SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
- **Registry key(s):** MaxSMB2Dialect
- **Values:**
- **Description:** This policy allows you to configure the maximum SMB2/3 version supported when acting as a client.

    It is recommended to not configure this policy and to let the system negociate the most suitable version.

    NOTE: do not configure this policy with a value below the one selected in the "Configure minimum SMB2 client dialect supported" policy, otherwise you could break SMB support on your system.

    Supported versions:
  - SMB 2.0.2
  - SMB 2.1.0 (Windows 7)
  - SMB 3.0.0 (Windows 8)
  - SMB 3.0.2 (windows 8.1)
  - SMB 3.1.1 (Windows 10, Windows Server 2016)

#### Enable support for TLS 1.2 only in WinHTTP

- **Registry path(s):**
  - SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp
  - SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp
- **Registry key(s):** DefaultSecureProtocols
- **Values:** 2048/`<delete>`
- **Description:** Enabling this policy will enable the support for TLS 1.2 only for applications based on WinHTTP and specifying the WINHTTP_OPTION_SECURE_PROTOCOLS flag.

    Disabling this policy will remove the DefaultSecureProtocols value, and restore the default behavior of WinHTTP.

    NOTE: for Windows 7, Windows Server 2008 R2, Windows Server 2012 and Windows 8 Embedded, you need to install the KB3140245 update before enabling this policy.

#### Enable advanced logging for Schannel

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
- **Registry key(s):** EventLogging
- **Values:** 1/2/3/4/5/6/7/0
- **Description:** Enabling this policy will enable detailed Schannel events generation. You can choose the desired level of verbosity.

  Logged events are available in the System event log.

#### Disable the strong-name bypass feature

- **Registry path(s):**
  - SOFTWARE\Microsoft\.NETFramework
  - SOFTWARE\Wow6432Node\Microsoft\.NETFramework
- **Registry key(s):** AllowStrongNameBypass
- **Values:** 0/1
- **Description:** Starting with the .NET Framework version 3.5 Service Pack 1 (SP1), strong-name signatures are not validated when an assembly is loaded into a full-trust xref:System.AppDomain object, such as the default xref:System.AppDomain for the MyComputer zone. This is referred to as the strong-name bypass feature. In a full-trust environment, demands for xref:System.Security.Permissions.StrongNameIdentityPermission always succeed for signed, full-trust assemblies regardless of their signature.

    The only restriction is that the assembly must be fully trusted because its zone is fully trusted. Because the strong name is not a determining factor under these conditions, there is no reason for it to be validated. Bypassing the validation of strong-name signatures provides significant performance improvements.

#### .NET Framework 4: enable strong cryptographic support

- **Registry path(s):**
  - SOFTWARE\Microsoft\.NETFramework\v4.0.30319
  - SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319
- **Registry key(s):**
  - SchUseStrongCrypto
  - SystemDefaultTlsVersions
- **Values:**
  - 0/1
  - 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for TLS 1.1 and TLS 1.2 in .NET Framework 4.

  If this setting is left unconfigured, TLS 1.1 and TLS 1.2 will be enabled by default for applications targeting .NET Framework 4.6 or higher and disabled otherwise.

#### .NET Framework 2: enable strong cryptographic support

- **Registry path(s):**
  - SOFTWARE\Microsoft\.NETFramework\v2.0.50727
  - SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727
- **Registry key(s):**
  - SchUseStrongCrypto
  - SystemDefaultTlsVersions
- **Values:**
  - 0/1
  - 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for TLS 1.1 and TLS 1.2 in .NET Framework 2.

  If this setting is left unconfigured, TLS 1.1 and TLS 1.2 will be disabled by default.

#### Multi-Protocol Unified Hello

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for Multi-Protocol Unified Hello. This protocol will never be used by Schannel SSP.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### PCT 1.0

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for PCT 1.0. This protocol will never be used by Schannel SSP.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### SSL 2.0

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for SSL 2.0. By default for Windows clients, SSL 2.0 is disabled.

    Note that SSL 2.0 is insecure and should not be enabled.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### SSL 3.0

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for SSL 3.0.

    SSL 3.0 is insecure and considered obsolete, and therefore should not be used. TLS 1.2 or better should be used instead, if possible.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### TLS 1.0

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for TLS 1.0.

    TLS 1.0, while historically considered secure, is now being deprecated by Microsoft and should be disabled. However, it may be required for backward compatibility.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### TLS 1.1

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for TLS 1.1.

    TLS 1.1, while historically considered secure, is now being deprecated by Microsoft and should be disabled. However, it may be required for backward compatibility.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### TLS 1.2

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for TLS 1.2. TLS 1.2 has no known security issues, and it is recommended to enable it.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### TLS 1.3

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for TLS 1.3. TLS 1.3 has no known security issues, and it is recommended to enable it.

    !! WARNING: This setting is only compatible with Windows 10 v1903 and later. Enabling this setting on older OS versions will break Schannel, and you will need to manually remove the SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3 key in the registry to fix it.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### DTLS 1.0

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for DTLS 1.0. Supported by Windows 7, Windows Server 2008 R2 and above.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### DTLS 1.2

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.2\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for DTLS 1.2. Supported by Windows 10 v1607 and above.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### DTLS 1.3

- **Registry path(s):**
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client
  - SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server
- **Registry key(s):**
  - Enabled
  - DisabledByDefault
- **Values:** 0/1
- **Description:** Enabling or disabling this policy will respectively enable or disable support for DTLS 1.3. Supported by Windows 10 v1903 and above.

    Changing this setting will require a restart of the computer before the setting will take effect.

#### NULL

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for NULL encryption ciphers. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_RSA_WITH_NULL_SHA
    TLS_RSA_WITH_NULL_SHA256

#### DES 56/56

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for DES 56/56. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    SSL_RSA_WITH_DES_CBC_SHA
    TLS_RSA_WITH_DES_CBC_SHA

#### RC2 40/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for RC2 40/128. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5

#### RC2 56/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for RC2 56/128. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    SSL_RSA_WITH_DES_CBC_SHA
    TLS_RSA_WITH_DES_CBC_SHA

#### RC2 128/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for RC2 128/128. This is a weak cipher and should not be enabled.

#### RC4 40/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for RC4 40/128. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    SSL_RSA_EXPORT_WITH_RC4_40_MD5
    TLS_RSA_EXPORT_WITH_RC4_40_MD5

#### RC4 56/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for RC4 56/128. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA

#### RC4 64/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for RC4 64/128. This is a weak cipher and should not be enabled.

#### RC4 128/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for RC4 128/128. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    SSL_RSA_WITH_RC4_128_MD5
    SSL_RSA_WITH_RC4_128_SHA
    TLS_RSA_WITH_RC4_128_MD5
    TLS_RSA_WITH_RC4_128_SHA

#### Triple DES 168

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for Triple-DES 168. This is a weak cipher and should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    SSL_CK_DES_192_EDE_CBC_WITH_MD5
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    TLS_RSA_WITH_3DES_EDE_CBC_SHA

#### AES 128/128

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for AES 128/128. Note that in order for Windows 2003 to support AES-128, hotfix KB948963 must be installed.

    It is recommended to enable it.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA256

#### AES 256/256

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for AES 256/256.  Note that in order for Windows 2003 to support AES-256, hotfix KB948963 must be installed.

    It is recommended to enable it.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA256

#### MD5

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the MD5 hashing algorithm. This is a weak hash algorithm, and it should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    SSL_CK_DES_192_EDE3_CBC_WITH_MD5
    SSL_CK_DES_64_CBC_WITH_MD5
    SSL_CK_RC4_128_EXPORT40_MD5
    SSL_CK_RC4_128_WITH_MD5
    TLS_RSA_EXPORT_WITH_RC4_40_MD5
    TLS_RSA_WITH_NULL_MD5
    TLS_RSA_WITH_RC4_128_MD5

#### SHA

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the SHA hashing algorithm. This is a weak hash algorithm, and it should not be enabled.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    TLS_DHE_DSS_WITH_DES_CBC_SHA
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
    TLS_RSA_WITH_3DES_EDE_CBC_SHA
    TLS_RSA_WITH_AES_128_CBC_SHA
    TLS_RSA_WITH_AES_256_CBC_SHA
    TLS_RSA_WITH_DES_CBC_SHA
    TLS_RSA_WITH_NULL_SHA
    TLS_RSA_WITH_RC4_128_SHA

#### SHA-256

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the SHA-256 hashing algorithm.

    It is recommended to enable it.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521
    TLS_RSA_WITH_AES_128_CBC_SHA256
    TLS_RSA_WITH_AES_256_CBC_SHA256
    TLS_RSA_WITH_NULL_SHA256

#### SHA-384

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the SHA-384 hashing algorithm.

    It is recommended to enable it.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521

#### SHA-512

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the SHA-512 hashing algorithm.

    It is recommended to enable it.

#### Diffie-Hellman

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the Diffie-Hellman key exchange algorithm.

    It is recommended to enable it.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    TLS_DHE_DSS_WITH_DES_CBC_SHA

#### Diffie-Hellman Server-side Key Size

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman
- **Registry key(s):** ServerMinKeyBitLength
- **Values:** 2048/3072/4096
- **Description:** Sets the minimum Diffie-Hellman ephemeral key size for TLS server.

    Please see Microsoft Security Advisory 3174644 for more information on DH modulus length. 4096 is the currently recommended minimum value.

#### Diffie-Hellman Client-side Key Size

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman
- **Registry key(s):** ClientMinKeyBitLength
- **Values:** 2048/3072/4096
- **Description:** Sets the minimum Diffie-Hellman ephemeral key size for TLS client.

    Please see Microsoft Security Advisory 3174644 for more information on DH modulus length. 4096 is the currently recommended minimum value.

#### PKCS

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the PKCS key exchange algorithm.

    It is recommended to enable it.

#### PKCS Client-side Key Size

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS
- **Registry key(s):** ClientMinKeyBitLength
- **Values:** 2048/3072/4096
- **Description:** Sets the minimum PKCS ephemeral key size for TLS client.

    Please see Microsoft Security Advisory 3174644 or https://support.microsoft.com/en-us/help/3174644/microsoft-security-advisory-updated-support-for-diffie-hellman-key-exc for more information on PKCS modulus length. 4096 is the currently recommended minimum value.

#### ECDH

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH
- **Registry key(s):** Enabled
- **Values:** 4294967295 (0xFFFFFFFF)/0
- **Description:** Enabling or disabling this policy will respectively enable or disable support for the Elliptic-Curve Diffie-Hellman key exchange algorithm.

    It is recommended to enable it.

    Changing this setting will have an effect on whether the following ciphers can be selected for use:

    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P521
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P521
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P521
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P521
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P521
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521

### Debugging policies

#### Enable Kernel Address Sanitizer

- **Registry path(s):** SYSTEM\CurrentControlSet\Control\Session Manager\Kernel
- **Registry key(s):** KasanEnabled
- **Values:** 0/1
- **Description:** The Kernel Address Sanitizer (KASAN) is a bug detection technology supported on Windows kernel drivers that enables you to detect several classes of illegal memory accesses, such as buffer overflows and use-after-free events.

    It requires you to enable KASAN on your system, and recompile your kernel driver with a specific MSVC compiler flag.

    This policy controls the support of KASAN in the kernel. Enabling this polic will enable the support of KASAN. Disabling this policy will disable the support of KASAN.

## Credits

- The Schannel configuration part is taken almost as-is from the [Crosse/SchannelGroupPolicy](https://github.com/Crosse/SchannelGroupPolicy) repository, a big kudo to him for his work :)
- The legacy MSS and the settings from the Microsoft Security Guide arte imported from the Microsoft Security Compliance Toolkit as-is
  - More information: <https://www.microsoft.com/en-us/download/details.aspx?id=55319>
- The Windows Defender Attack Surface Reduction section is ported from @MichaelGrafnetter [project](<https://github.com/MichaelGrafnetter/defender-asr-admx>)