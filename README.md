<!--
SPDX-FileCopyrightText: 2024 DB Systel GmbH

SPDX-License-Identifier: Apache-2.0
-->

# Compliance Assistant

**Compliance Assistant** is a comprehensive toolset designed to assist with creating and managing Software Bill of Materials (SBOMs). It helps in enriching SBOMs with licensing and copyright information and checks for Ppen Source license compliance using data from [ClearlyDefined](https://clearlydefined.io/).

## Features

- **SBOM Generation**: Automatically generate a CycloneDX SBOM from a specified code repository.
- **SBOM Enrichment**: Enhance an existing SBOM with detailed licensing and copyright information using ClearlyDefined data.
- **SBOM Parsing**: Extract specific information from a CycloneDX SBOM.
- **License and Copyright Information Retrieval**: Fetch licensing and copyright details for a single package from ClearlyDefined.

## Requirements

- Python 3.10+
- Internet connection for accessing ClearlyDefined services

## Installation

### Install and run via pipx (Recommended)

[pipx](https://pypa.github.io/pipx/) makes installing and running Python programs easier and avoid conflicts with other packages. Install it with

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

For full functionality, the following pieces of software are recommended:

* [Docker](https://www.docker.com/)

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

In the following, we will just use `compliance-assistant`

### Command Structure

```bash
compliance-assistant [global-options] <command> [command-options]
```

### Commands

Please run `compliance-assistant --help` to get an overview of the commands and global options.

For each command, you can get detailed options, e.g. `compliance-assistant sbom-enrich --help`.

### Examples

* Create an SBOM for the current directory: `compliance-assistant sbom-generate -d .`
* Enrich an SBOM with ClearlyDefined data: `compliance-assistant sbom-enrich -f /tmp/my-sbom.json -o /tmp/my-enriched-sbom.json`
* Extract certain data from an SBOM: `compliance-assistant sbom-parse -f /tmp/my-enriched-sbom.json -e purl,copyright,name`
* Gather ClearlyDefined licensing/copyright information for one package: `compliance-assistant clearlydefined -p pkg:pypi/inwx-dns-recordmaster@0.3.1`


## Development and Contribution

We welcome contributions to improve Compliance Assistant. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for all information.


## License

The content of this repository is licensed under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).

There may be components under different, but compatible licenses or from different copyright holders. The project is REUSE compliant which makes these portions transparent. You will find all used licenses in the [LICENSES](./LICENSES/) directory.

The project is has been started by the [OpenRail Association](https://openrailassociation.org). You are welcome to [contribute](./CONTRIBUTING.md)!
