# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-11-23

### Added
- README: added best practice synchronization frequency warning. Maximum once per day.

## [1.0.2] - 2026-01-08

### Fixed
- `ManagerCanOverrideDuration` now defaults to `false` on the created products.

## [1.0.1] - 2023-01-30

### Changed
- Use `[System.Collections.Generic.Dictionary]::new()` instead of `New-Object` for the request headers.

## [1.0.0] - 2022-02-15

Initial release with base functionality: synchronizes Exchange on-premises shared mailboxes to HelloID Self service products.
