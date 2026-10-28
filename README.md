# Diatonic Agent SDK

A provider-neutral agent pipeline SDK from **Diatonic OS**, a **Chromatix Studios** project by founder **Drew Fortini (@iamdrewfortini)**. This public repository is an exploration prepared for the 10-day Meta Hackathon. The installable Python distribution keeps its compatibility name, `diatonic-meta-pipeline`; the user-facing project name is Diatonic Agent SDK.

## Source and release status

This repository contains source candidate **0.3.5** (`pyproject.toml`), copied from the `feature/handoff-native-035` branch at commit `d4f427ee2bcc168feb53db3cb292183917098e27`. That candidate is source code for evaluation; it is not a claim of a deployed or independently released 0.3.5. The originating private environment reported deployment **0.3.4** and historical verification for that version. Those are historical facts about that environment, not public release assurance for this repository.

The included tests are source-candidate tests. The vendor schema comparison test skips when the separately held private schema bundle is absent; the bundle and its contents are intentionally not included. A Temporal integration test also skips if its optional local test server is unavailable. CI reports skips normally and does not download private assets.

## Providers and boundaries

The SDK exposes provider-neutral contracts and adapters. Configure only providers you have independently selected and authorized; credentials are supplied at runtime and are not part of this package. The repository contains no signed production feed authority or key pins. Example credentials in tests are synthetic fixtures.

## Install

Requires Python 3.11 or newer. Install from a local checkout:

```sh
python -m venv .venv
. .venv/bin/activate
pip install .
meta-pipeline --help
```

Package distribution name: `diatonic-meta-pipeline`. CLI: `meta-pipeline`.

## Development

For the Linux x86_64 / Python 3.12 CI dependency set, `requirements-ci.lock` pins public PyPI wheel versions and SHA-256 hashes, derived from the previously verified runtime wheel manifest for 0.3.4 and build wheel manifest for 0.3.5. GitHub Actions and GitLab CI create the required `.venv`, install only from public PyPI with hashes, run the tests, and build/install a wheel.

The test suite uses temporary directories and synthetic inputs. It does not require a live provider account. The CI workflow does not install private vendor material.

## License

Copyright (c) 2026 Diatonic OS / Chromatix Studios. All rights reserved. No open-source license has been selected for this repository yet.
