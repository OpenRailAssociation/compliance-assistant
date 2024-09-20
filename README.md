<!--
SPDX-FileCopyrightText: 2024 DB Systel GmbH

SPDX-License-Identifier: Apache-2.0
-->

# Compliance Assistant

[![Test suites](https://github.com/OpenRailAssociation/compliance-assistant/actions/workflows/test.yaml/badge.svg)](https://github.com/OpenRailAssociation/compliance-assistant/actions/workflows/test.yaml)
[![REUSE status](https://api.reuse.software/badge/github.com/OpenRailAssociation/compliance-assistant)](https://api.reuse.software/info/github.com/OpenRailAssociation/compliance-assistant)
[![The latest version of Compliance Assistant can be found on PyPI.](https://img.shields.io/pypi/v/compliance-assistant.svg)](https://pypi.org/project/compliance-assistant/)
[![Information on what versions of Python Compliance Assistant supports can be found on PyPI.](https://img.shields.io/pypi/pyversions/compliance-assistant.svg)](https://pypi.org/project/compliance-assistant/)

**Compliance Assistant** is a comprehensive toolset designed to assist with creating and managing Software Bill of Materials (SBOMs). It helps in enriching SBOMs with licensing and copyright information and checks for Open Source license compliance using data from [ClearlyDefined](https://clearlydefined.io/).

<!-- TOC -->
- [Compliance Assistant](#compliance-assistant)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Development and Contribution](#development-and-contribution)
  - [License](#license)
<!-- /TOC -->

## Features

- **SBOM Generation**: Automatically generate a CycloneDX SBOM from a specified code repository.
- **SBOM Enrichment**: Enhance an existing SBOM with detailed licensing and copyright information using ClearlyDefined data.
- **SBOM Parsing**: Extract specific information from a CycloneDX SBOM.
- **License and Copyright Information Retrieval**: Fetch licensing and copyright details for a single package from ClearlyDefined.
- **License compliance support**: Extract and unify licenses from SBOM, suggest possible license outbound candidates

Some of these features are made possible by excellent programs such as [flict](https://github.com/vinland-technology/flict), [cdxgen](https://github.com/CycloneDX/cdxgen) and [syft](https://github.com/anchore/syft/).

## Requirements

- Python 3.10+
- Internet connection for accessing ClearlyDefined services
- At least one SBOM generator:
  - [syft](https://github.com/anchore/syft/)
  - [cdxgen](https://github.com/CycloneDX/cdxgen)
  - [Docker](https://www.docker.com/) for generating SBOMs with the dockerized cdxgen

## Installation

### Install and run via pipx (Recommended)

[pipx](https://pypa.github.io/pipx/) makes installing and running Python programs easier and avoids conflicts with other packages. Install it with

```sh
pip3 install pipx
```

The following one-liner both installs and runs this program from [PyPI](https://pypi.org/project/compliance-assistant/):

```sh
pipx run compliance-assistant
```

If you want to be able to use compliance-assistant without prepending it with `pipx run` every time, install it globally like so:

```sh
pipx install compliance-assistant
```

compliance-assistant will then be available in `~/.local/bin`, which must be added to your `$PATH`.

After this, make sure that `~/.local/bin` is in your `$PATH`. On Windows, the required path for your environment may look like `%USERPROFILE%\AppData\Roaming\Python\Python310\Scripts`, depending on the Python version you have installed.

To upgrade compliance-assistant to the newest available version, run this command:

```sh
pipx upgrade compliance-assistant
```


### Other installation methods

You may also use pure `pip` or `poetry` to install this package.


## Usage

The Compliance Assistant provides multiple commands to facilitate different tasks. Each command is invoked through the `compliance-assistant` command-line interface with specific options.

Depending on your exact installation method, this may be one of

```sh
# Run via pipx
pipx run compliance-assistant
# Installation via pipx or pip
compliance-assistant
# Run via poetry
poetry run compliance-assistant
```

In the following, we will just use `compliance-assistant`.

### Command Structure

```bash
compliance-assistant <command> [<subcommand>] [subcommand-options]
```

### Commands

Please run `compliance-assistant --help` to get an overview of the commands and global options.

For each command, you can get detailed options, e.g., `compliance-assistant sbom enrich --help`.

### Examples

* Create an SBOM for the current directory using [syft](https://github.com/anchore/syft/): `compliance-assistant sbom generate -g syft -d . -o /tmp/my-sbom.json`
* Enrich an SBOM with ClearlyDefined data: `compliance-assistant sbom enrich -f /tmp/my-sbom.json -o /tmp/my-enriched-sbom.json`
* Extract certain data from an SBOM: `compliance-assistant sbom parse -f /tmp/my-enriched-sbom.json -e purl,copyright,name`
* Gather ClearlyDefined licensing/copyright information for one package: `compliance-assistant clearlydefined fetch -p pkg:pypi/inwx-dns-recordmaster@0.3.1`
* Get all licenses found in the enriched SBOM: `compliance-assistant licensing list -f /tmp/my-enriched-sbom.json -o plain`
* Get license outbound candidate based on licenses from SBOM: `compliance-assistant licensing outbound -f /tmp/my-enriched-sbom.json`

### Run as GitHub workflow

You may also use GitHub workflows to generate an SBOM regularly, e.g., on each published release:

```yaml
name: Generate and enrich SBOM

on:
  release:
    types: [published]

jobs:
  # Generate the SBOM with syft and enrich the generated SBOM
  sbom-generate-and-enrich:
    runs-on: ubuntu-22.04
    needs: sbom-gen
    steps:
      # Install compliance-assistant
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: "pip"
      - name: Install compliance-assistant
        run: pip install compliance-assistant
      # Install syft
      - run: mkdir -p ~/.local/bin
      - name: Install syft
        run: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ~/.local/bin
      # Generate SBOM with syft via compliance-assistant
      - name: Generate SBOM with syft
        run: poetry run compliance-assistant sbom generate -g syft -d . -o ${{ runner.temp }}/sbom-raw.json
      # Enrich SBOM with compliance-assistant
      - name: Enrich SBOM
        run: compliance-assistant sbom enrich -f ${{ runner.temp }}/sbom-raw.json -o ${{ runner.temp }}/sbom-enriched.json
      # Upload enriched SBOM as artifact
      - name: Store enriched SBOM as artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom-enriched
          path: ${{ runner.temp }}/sbom-enriched.json
```


## Development and Contribution

We welcome contributions to improve Compliance Assistant. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for all information.


## License

The content of this repository is licensed under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).

There may be components under different, but compatible licenses or from different copyright holders. The project is REUSE compliant which makes these portions transparent. You will find all used licenses in the [LICENSES](./LICENSES/) directory.

The project has been started by the [OpenRail Association](https://openrailassociation.org). You are welcome to [contribute](./CONTRIBUTING.md)!
