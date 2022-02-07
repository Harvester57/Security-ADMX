# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [v1.0.18] - 2022-02-07

### Added
- "Disable standard user in safe boot mode" policy (https://github.com/Harvester57/Security-ADMX/issues/5)

## [v1.0.17] - 2021-01-09

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