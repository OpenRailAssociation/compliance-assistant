# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""
Toolset that helps you with creating and interacting with SBOMs, enriching with
licensing and copyright information, and checking for Open Source license
compliance
"""

import argparse
import logging
import sys

from . import __version__
from ._clearlydefined import (
    get_clearlydefined_license_and_copyright,
    print_clearlydefined_result,
    purl_to_cd_coordinates,
)
from ._helpers import dict_to_json
from ._licensing import get_outbound_candidate, list_all_licenses
from ._logging import configure_logger
from ._sbom_enrich import enrich_sbom_with_clearlydefined
from ._sbom_generate import generate_cdx_sbom
from ._sbom_parse import extract_items_from_cdx_sbom

# Main parser with root-level flags
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--version", action="version", version="%(prog)s " + __version__)

# Initiate first-level subcommands
subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

# Common flags, usable for all effective subcommands
common_flags = argparse.ArgumentParser(add_help=False)  # No automatic help to avoid duplication
common_flags.add_argument("-v", "--verbose", action="store_true", help="Verbose output (DEBUG)")

# SBOM commands
parser_sbom = subparsers.add_parser(
    "sbom",
    help="Commands to generate, enrich, and parse SBOMs",
)
subparser_sbom = parser_sbom.add_subparsers(
    dest="sbom_command",
    help="Available sbom commands",
)

# SBOM Generator
parser_sbom_gen = subparser_sbom.add_parser(
    "generate",
    help="Generate a CycloneDX SBOM using the cdxgen Docker image",
    parents=[common_flags],
)
parser_sbom_gen.add_argument(
    "-d",
    "--directory",
    help="Path to the directory of the code repository that shall be analysed",
    required=True,
)
parser_sbom_gen.add_argument(
    "-o",
    "--output",
    help=(
        "Path where the generated SBOM shall be saved. "
        "If unset, it will be stored in a temporary directory. Use '-' to print it to stdout."
    ),
)

# Enrich a SBOM with ClearlyDefined data
parser_sbom_enrich = subparser_sbom.add_parser(
    "enrich",
    help="Enrich a CycloneDX SBOM and its licensing/copyright data via ClearlyDefined",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    parents=[common_flags],
)
parser_sbom_enrich.add_argument(
    "-f",
    "--file",
    help="Path to the SBOM that shall be enriched",
    required=True,
)
parser_sbom_enrich.add_argument(
    "-o",
    "--output",
    help="Path where the enriched SBOM shall be saved. Use '-' to print it to stdout.",
    required=True,
)
parser_sbom_enrich.add_argument(
    "--batch-size",
    help="The number of packages to request information for from ClearlyDefined at once.",
    default=25,
    type=int,
)
parser_sbom_enrich.add_argument(
    "--no-batches",
    help=(
        "Request information for one package at a time from ClearlyDefined API, and not in batches."
    ),
    action="store_true",
)
parser_sbom_enrich.add_argument(
    "--http-debug", help="Activate extreme HTTP logging", action="store_true"
)

# SBOM Parser
parser_sbom_read = subparser_sbom.add_parser(
    "parse",
    help="Parse a CycloneDX SBOM and extract contained information",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    parents=[common_flags],
)
parser_sbom_read.add_argument(
    "-f",
    "--file",
    help="Path to the CycloneDX SBOM (JSON format) that shall be parsed",
    required=True,
)
parser_sbom_read.add_argument(
    "-e",
    "--extract",
    default="purl,licenses-short",
    help="Information that shall be retrieved from each contained component. Comma-separated list.",
)
parser_sbom_read.add_argument(
    "-o",
    "--output",
    default="json",
    choices=["json", "dict", "none"],
    help="Desired output format.",
)
parser_sbom_read.add_argument(
    "--no-simplify",
    help="Do not simplify SPDX license expression using flict. May increase speed",
    action="store_true",
)

# ClearlyDefined
parser_cd = subparsers.add_parser(
    "clearlydefined",
    help="Use ClearlyDefined to fetch licensing and copyright information, and run coversions",
)
subparser_cd = parser_cd.add_subparsers(
    dest="clearlydefined_command",
    help="Available clearlydefined commands",
)

# ClearlyDefined convert subcommand
parser_cd_convert = subparser_cd.add_parser(
    "convert",
    help="Convert a Package URL to ClearlyDefined coordinates",
    parents=[common_flags],
)
parser_cd_convert.add_argument(
    "-p",
    "--purl",
    help="A Package URL (purl) to convert to ClearlyDefined coordinates.",
)

# ClearlyDefined fetch subcommand
parser_cd_fetch = subparser_cd.add_parser(
    "fetch",
    help="Fetch licensing and copyright information of packages from ClearlyDefined",
    parents=[common_flags],
)
parser_cd_fetch.add_argument(
    "--http-debug", help="Activate extreme HTTP logging", action="store_true"
)
parser_cd_fetch_exclusive = parser_cd_fetch.add_mutually_exclusive_group(required=True)
parser_cd_fetch_exclusive.add_argument(
    "-p",
    "--purl",
    help=(
        "The purl for which ClearlyDefined licensing information is searched. "
        "Cannot be combined with -c"
    ),
)
parser_cd_fetch_exclusive.add_argument(
    "-c",
    "--coordinates",
    help=(
        "The ClearlyDefined coordinates for which licensing information is searched. "
        "Canot be combined with -p."
    ),
)


# License Compliance
parser_licensing = subparsers.add_parser(
    "licensing",
    help="Help with checking and reaching Open Source license compliance",
)
subparser_licensing = parser_licensing.add_subparsers(
    dest="licensing_command",
    help="Available licensing commands",
)

# List licenses
parser_licensing_list = subparser_licensing.add_parser(
    "list",
    help="List all detected licenses",
    parents=[common_flags],
)
parser_licensing_list.add_argument(
    "-f",
    "--file",
    help="Path to the CycloneDX SBOM (JSON format) from which licenses are read",
    required=True,
)
parser_licensing_list.add_argument(
    "-o",
    "--output",
    default="json",
    choices=["json", "dict", "plain", "none"],
    help="Desired output format.",
)
parser_licensing_list.add_argument(
    "--no-simplify",
    help="Do not simplify SPDX license expression using flict. May increase speed",
    action="store_true",
)

# License outbound candidate
parser_licensing_outbound = subparser_licensing.add_parser(
    "outbound",
    help="Suggest possible outbound licenses based on found licenses in an SBOM",
    parents=[common_flags],
)
parser_licensing_outbound.add_argument(
    "-f",
    "--file",
    help="Path to the CycloneDX SBOM (JSON format) from which licenses are read",
    required=True,
)
parser_licensing_outbound.add_argument(
    "-o",
    "--output",
    default="json",
    choices=["json", "dict", "plain", "none"],
    help="Desired output format. json and dict contain the most helpful output",
)
parser_licensing_outbound.add_argument(
    "--no-simplify",
    help="Do not simplify SPDX license expression using flict. May increase speed",
    action="store_true",
)


def main():  # pylint: disable=too-many-branches, too-many-statements
    """Main function"""

    args = parser.parse_args()

    # Set logger
    configure_logger(args=args)

    # Debug arguments
    logging.debug(args)

    # Generate SBOM with cdxgen
    # SBOM commands
    if args.command == "sbom":
        if args.sbom_command == "generate":
            generate_cdx_sbom(directory=args.directory, output=args.output)

        # Enrich SBOM by ClearlyDefined data
        elif args.sbom_command == "enrich":
            enrich_sbom_with_clearlydefined(
                sbom_file=args.file,
                output_file=args.output,
                in_batches=not args.no_batches,
                batch_size=args.batch_size,
            )

        # Parse info from SBOM
        elif args.sbom_command == "parse":
            # Convert comma-separated information to list
            info = args.extract.split(",")
            extraction = extract_items_from_cdx_sbom(
                sbom_path=args.file, information=info, flict_simplify=not args.no_simplify
            )
            if args.output == "json":
                print(dict_to_json(data=extraction))
            elif args.output == "dict":
                print(extraction)
            elif args.output == "none":
                pass

        # No sbom subcommand given, show help
        else:
            parser_sbom.print_help()

    # ClearlyDefined commands
    elif args.command == "clearlydefined":
        # ClearlyDefined conversion
        if args.clearlydefined_command == "convert":
            print(purl_to_cd_coordinates(purl=args.purl))

        elif args.clearlydefined_command == "fetch":
            if args.purl:
                coordinates = purl_to_cd_coordinates(purl=args.purl)
            else:
                coordinates = args.coordinates

            print_clearlydefined_result(
                results=get_clearlydefined_license_and_copyright(coordinates)
            )

    # License compliance commands
    elif args.command == "licensing":
        # List all detected licenses in an SBOM, unified and sorted
        if args.licensing_command == "list":
            all_licenses = list_all_licenses(
                sbom_path=args.file, flict_simplify=not args.no_simplify
            )
            if args.output == "json":
                print(dict_to_json(data=all_licenses))
            elif args.output == "dict":
                print(all_licenses)
            elif args.output == "plain":
                print("\n".join(all_licenses))
            elif args.output == "none":
                pass

        # Suggest possible outbound licenses based on detected licenses in an SBOM
        elif args.licensing_command == "outbound":
            outbound_candidates = get_outbound_candidate(
                sbom_path=args.file, simplify=not args.no_simplify
            )
            if args.output == "json":
                print(dict_to_json(data=outbound_candidates))
            elif args.output == "dict":
                print(outbound_candidates)
            elif args.output == "plain":
                print("\n".join(outbound_candidates.get("outbound_candidate")))
            elif args.output == "none":
                pass

        # No licensing subcommand given, show help
        else:
            parser_licensing.print_help()

    else:
        logging.critical("No valid command provided!")
        sys.exit(1)


if __name__ == "__main__":
    main()
