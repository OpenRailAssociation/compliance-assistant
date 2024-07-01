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
from ._helpers import delete_file, dict_to_json
from ._sbom_create import generate_cdx_sbom
from ._sbom_full import enrich_sbom_with_clearlydefined
from ._sbom_parse import extract_items_from_cdx_sbom

parser = argparse.ArgumentParser(description=__doc__)
subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

# Full SBOM generation and enrichment process
parser_sbom_full = subparsers.add_parser(
    "full-sbom",
    help="Generate a CycloneDX SBOM and enrich its licensing data via ClearlyDefined",
)
parser_sbom_full.add_argument(
    "-d",
    "--directory",
    help="Path to the directory of the code repository that shall be analysed",
    required=True,
)
parser_sbom_full.add_argument(
    "-o",
    "--output",
    help="Path where the enriched SBOM shall be saved",
    required=True,
)

# SBOM Generator
parser_sbom_gen = subparsers.add_parser(
    "generate-sbom",
    help="Generate a CycloneDX SBOM",
)
parser_sbom_gen.add_argument(
    "-d",
    "--directory",
    help="Path to the directory of the code repository that shall be analysed",
    required=True,
)

# SBOM Parser
parser_sbom_read = subparsers.add_parser(
    "parse-sbom",
    help="Parse a CycloneDX SBOM and extract contained information",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
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
    help="Desired output format. Can be one of: json, dict, none",
)

# ClearlyDefined
parser_cd = subparsers.add_parser(
    "clearlydefined",
    help="Gather license information from ClearlyDefined for a package",
)
parser_cd_exclusive = parser_cd.add_mutually_exclusive_group(required=True)
parser_cd_exclusive.add_argument(
    "-p",
    "--purl",
    help=(
        "The purl for which ClearlyDefined licensing information is searched. "
        "If -c is used, this is preferred."
    ),
)
parser_cd_exclusive.add_argument(
    "-c",
    "--coordinates",
    help=(
        "The ClearlyDefined coordinates for which ClearlyDefined licensing information is searched"
    ),
)
parser_cd_exclusive.add_argument(
    "--purl-to-coordinates",
    help=(
        "Convert a Package URL (purl) to ClearlyDefined coordinates, and show result. "
        "Cannot be combined with -p and -c."
    ),
)

# General flags
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
parser.add_argument("--version", action="version", version="%(prog)s " + __version__)


def configure_logger(args) -> logging.Logger:
    """Set logging options"""
    log = logging.getLogger()
    logging.basicConfig(
        encoding="utf-8",
        format="%(levelname)s: %(message)s",
        level=(logging.DEBUG if args.verbose else logging.INFO),
    )

    return log


def main():
    """Main function"""

    args = parser.parse_args()

    # Set logger
    configure_logger(args=args)

    # Find out which command is called
    if args.command == "full-sbom":
        # Generate SBOM with cdxgen
        sbom_raw_path = generate_cdx_sbom(args.directory)
        # Enrich SBOM by ClearlyDefined data
        enrich_sbom_with_clearlydefined(sbom_raw_path, args.output)
        # Delete first SBOM
        delete_file(sbom_raw_path)

    elif args.command == "generate-sbom":
        print(f"Generated SBOM saved to {generate_cdx_sbom(args.directory)}")

    elif args.command == "parse-sbom":
        # Convert comma-separated information to list
        info = args.extract.split(",")
        extraction = extract_items_from_cdx_sbom(args.file, information=info, use_flict=True)
        if args.output == "json":
            print(dict_to_json(extraction))
        elif args.output == "dict":
            print(extraction)
        elif args.output == "none":
            pass

    elif args.command == "clearlydefined":
        if args.purl_to_coordinates:
            print(purl_to_cd_coordinates(args.purl_to_coordinates))
        elif args.purl:
            print_clearlydefined_result(
                get_clearlydefined_license_and_copyright(
                    coordinates=purl_to_cd_coordinates(args.purl)
                )
            )
        elif args.coordinates:
            print_clearlydefined_result(get_clearlydefined_license_and_copyright(args.coordinates))
    else:
        logging.critical("No valid command provided!")
        sys.exit(1)


if __name__ == "__main__":
    main()
