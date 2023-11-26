# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [v1.0.31] - 2023-11-26
### Added
- Support for DTLS 1.3 in Schannel section

## [v1.0.30] - 2023-11-26
### Fixed
- Typo in the MsCacheV2 hardening policy description : MSCHAPv2 -> MsCacheV2
- Improved the overall wording of the description

## [v1.0.29] - 2023-03-14
### Added
- Added the new policy "Enable support for TLS 1.2 only" for WinHTTP (https://github.com/Harvester57/Security-ADMX/issues/16)
  - Thanks @Deas-h for the suggestion :)

## [v1.0.28] - 2023-01-28
### Changed
- Updated the default value for PBKDF2-HMAC-SHA1 rounds and the associated policy description

## [v1.0.27] - 2023-01-08
### Added
- Added "Prevent standard users to install root certificates" policy
- Added a new category of policies, for Domain Controllers specific parameters
  - This is empty for now, will soon be populated...

## [v1.0.26] - 2022-12-03
### Added
- Added "Configure the maximum/minimum SMB2 client dialect supported" policies
- Added a NOTE to the "Enable PowerShell Constrained Language Mode" policy

### Changed
- Updated the "Available Settings" pages

### Fixed
- Typos and wording, both for en-US and fr-FR templates

## [v1.0.25] - 2022-11-19
### Added
- Configuration profiles for Schannel TLS cipher suites
  - Loosely based on [Mozilla recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS), [ANSSI recommendations](https://www.ssi.gouv.fr/guide/recommandations-de-securite-relatives-a-tls/) and best practices

## [v1.0.24] - 2022-11-17
### Fixed
- Apply "EnableCertPaddingCheck" as REG_SZ, not DWORD
- Improve Schannel-related descriptions

## [v1.0.23] - 2022-10-17
### Added
- "Disable the strong-name bypass feature" policy for .NET Framework
  - More infos in the .NET documentation: https://learn.microsoft.com/en-us/dotnet/standard/assembly/disable-strong-name-bypass-feature
- "Disable the SAM server TCP listener"
  - More details in this Twitter thread: https://twitter.com/agowa338/status/1581205232238796800
  - Credits to @tyranid for the registry key

## [v1.0.22] - 2022-08-29
### Added
- "Disable Time-Travel Debugging" policy (https://github.com/Harvester57/Security-ADMX/issues/11)
- "Remove current working directory from DLL search" policy (https://github.com/Harvester57/Security-ADMX/issues/10)

### Fixed
- Typo in the fr-FR description of the "Number of PBKDF2 iterations for cached logons credentials hashing" policy

## [v1.0.21] - 2022-08-12
### Fixed
- Typo in the "Disabled list of the NET 2 Strong Crypto" policy (https://github.com/Harvester57/Security-ADMX/issues/9)

## [v1.0.20] - 2022-07-23
### Added
- "Disable the WPBT functionnality" policy (https://github.com/Harvester57/Security-ADMX/issues/8)

## [v1.0.19] - 2022-05-23
### Added
- New policy to enable/disable kCET support on 21H2+ systems
  - Thanks to Yarden Shafir (@yarden_shafir) and Connor McGarr (@33y0re)
  - Cf. https://connormcgarr.github.io/hvci/ (#Conclusion)

## [v1.0.18] - 2022-02-07
### Added
- "Disable standard user in safe boot mode" policy (https://github.com/Harvester57/Security-ADMX/issues/5)

## [v1.0.17] - 2022-01-09
### Added
- Strict Authenticode signatures verification (https://github.com/Harvester57/Security-ADMX/issues/4)

## [v1.0.16] - 2021-12-30
### Changed
- Changed the default value for the MSCHAPv2 hashing algorithm required rounds to 1 048 576 (`NL$IterationCount = 1024`)

### Fixed
- Fixed a typo in fr-FR

### Removed
-  Remove support for Diffie-Hellman and PKCS 1024 bit modulus

## [v1.0.15] - 2021-12-28
### Changed
- Reworked the MSCHAPv2 hashing algorithm description, and changed the minimum value allowed for the `NL$IterationCount` key
