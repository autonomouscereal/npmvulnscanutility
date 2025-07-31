# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2025-07-31
### Added
- Resolve group names properly via `/groups/{id}` endpoint with caching.
- New `CxOneAPI.get_group()` helper.
- Script now outputs accurate group names.

### Fixed
- `.env` SSL verification toggle documented.

## [0.1.0] - 2025-07-31
### Added
- Initial Python migration from PowerShell scripts.
- `CxOneSession` for authentication via refresh token.
- `CxOneAPI` minimal REST helper.
- CSV report generation script for project maturity (Levels 2-4).
- `.env.example` for environment variables.
- Extensive `README.md`.
- `TODO.md` and `CHANGELOG.md`.
