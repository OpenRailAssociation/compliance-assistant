# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Open Source License Compliance helpers"""

import logging

from license_expression import ExpressionError, Licensing, get_spdx_licensing

from ._flict import flict_outbound_candidate, flict_simplify, flict_simplify_list
from ._sbom_parse import extract_items_from_cdx_sbom


def _extract_license_expression_and_names_from_sbom(
    sbom_path: str, use_flict: bool = False
) -> tuple[list[str], list[str]]:
    """Exract all SPDX expressions and license names from an SBOM"""
    lic_expressions = []
    lic_names = []

    for item in extract_items_from_cdx_sbom(
        sbom_path, information=["name", "purl", "licenses-short"], use_flict=use_flict
    ):
        licenses_short: list[dict] = item.get("licenses-short", [])

        for entry in licenses_short:
            if lic_expression := entry.get("expression", ""):
                lic_expressions.append(lic_expression)
            # Use license name instead
            else:
                lic_dict: dict = entry.get("license", {})
                if lic_name := lic_dict.get("name", ""):
                    lic_names.append(lic_name)

    # Make expressions and names unique, and sort them
    expressions = sorted(list(set(lic_expressions)))
    # If using flict, simplify these found licenses. Will reduce possible
    # duplicates and fix problematic SPDX expressions (e.g. MPL-2.0+)
    # That's far more performant than doing that for each license in the SBOM
    if use_flict:
        expressions = flict_simplify_list(expressions)
    names = sorted(list(set(lic_names)))

    return expressions, names


def list_all_licenses(sbom_path: str, use_flict: bool = False) -> list[str]:
    """List all detected licenses of an SBOM, unified and sorted"""
    expressions, names = _extract_license_expression_and_names_from_sbom(sbom_path, use_flict)

    # Combine both SPDX expressions and names, sort and unify again
    return sorted(list(set(expressions + names)))


def _validate_spdx_licenses(licenses: list[str]) -> list[str]:
    """Check a list of licenses for whether they are valid SPDX. Only return
    valid licenses, warn on bad expression"""
    valid_licenses: list[str] = []
    spdx: Licensing = get_spdx_licensing()

    for lic in licenses:
        try:
            spdx.parse(lic, validate=True)
            valid_licenses.append(lic)
        except ExpressionError as exc:
            logging.error(
                "The license expression/name '%s' found in the given SBOM is no valid SPDX "
                "expression. Therefore, it cannot be taken into consideration for the evaluation. "
                "Error message: %s",
                lic,
                exc,
            )

    return valid_licenses


def _craft_single_spdx_expression(licenses: list[str]):
    """Convert multiple SPDX licenses and expressions into one large expression"""
    # Put all licenses into brackets
    licenses = [f"({lic})" for lic in licenses]

    return " AND ".join(licenses)


def get_outbound_candidate(sbom_path: str, simplify: bool = True) -> dict[str, str | list[str]]:
    """Get license outbound candidates from an SBOM"""
    logging.info("Extracting, simplifying and validating found licenses. This can take a while")
    licenses_in_sbom = list_all_licenses(sbom_path, use_flict=simplify)

    # Check whether all licenses are valid SPDX expressions
    licenses = _validate_spdx_licenses(licenses_in_sbom)

    # Combine single licenses into one large SPDX license expression
    expression = _craft_single_spdx_expression(licenses)
    if simplify:
        logging.debug("Simplify crafted license expression %s", expression)
        expression = flict_simplify(expression, output_format="text")
        logging.debug("Simplified licenses expression: %s", expression)

    # Get outbound candidate
    logging.info("Calculating possible outbound candidates")
    outbound_candidate: str = flict_outbound_candidate(expression, output_format="text")

    return {
        "licenses_in_sbom": licenses_in_sbom,
        "considered_licenses": licenses,
        "checked_expression": expression,
        "outbound_candidate": outbound_candidate,
    }
