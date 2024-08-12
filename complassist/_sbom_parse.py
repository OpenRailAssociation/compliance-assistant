# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Parse a CycloneDX SBOM and extract certain information"""

import logging

from ._flict import flict_simplify
from ._helpers import read_json_file


def _unify_licenses_data(licenses_data: list[dict], use_flict: bool = True) -> list[dict]:
    """Convert a list of license ids/expressions/names to a single string,
    either an expression or a name"""

    # Case 1: no data
    if len(licenses_data) == 0:
        return []
    # Case 2: only one entry
    if len(licenses_data) == 1:
        return licenses_data
    # Case 3: more than one license entry
    if len(licenses_data) > 1:
        # Find out whether we're only handling SPDX expression or also free-text fields
        types = {key for d in licenses_data for key in d}

        # Only SPDX expressions, so combine SPDX expressions with "AND"
        if types == {"spdx-expression"}:
            expressions_list = [
                f"({expression})" for d in licenses_data for _, expression in d.items()
            ]
            spdx_expression = " AND ".join(expressions_list)
            if use_flict:
                spdx_expression = flict_simplify(spdx_expression, output_format="text")
            return [{"spdx-expression": spdx_expression}]

        # At least one free-text license contained, so we need to form a new free-text field
        logging.debug(
            "Multiple license data fields found, and at least one is no valid SPDX expression. "
            "Will combine them into a free-text string."
        )
        licensevalues = [licvalue for d in licenses_data for _, licvalue in d.items()]
        return [{"free-text": " / ".join(licensevalues)}]

    # Fallback, which shouldn't happen
    return []


def _license_short_to_valid_cdx_item(short_license: list[dict]) -> list[dict]:
    """Convert our own short license expression back to a valid CycloneDX license object"""
    # A license is present
    if short_license:
        # SPDX expression
        if expr := short_license[0].get("spdx-expression"):
            return [{"expression": expr}]
        if freetext := short_license[0].get("free-text"):
            return [{"license": {"name": freetext}}]
    # No license present
    return []


def _shorten_cdx_licenses_item(licenses: list, use_flict: bool = True) -> list:
    """Extract relevant license fields in a CycloneDX SBOM
    (id, expression, name) in a simplified form (only expression or name)"""
    collection: list[dict] = []
    for licdata in licenses:
        error = False
        # If "license" key exists, it's either "id" or "name"
        if "license" in licdata:
            # If only one license ID, treat it as expression (which is compliant
            # with SPDX spec)
            if expr := licdata["license"].get("id"):
                collection.append({"spdx-expression": expr})
            elif name := licdata["license"].get("name"):
                collection.append({"free-text": name})
            else:
                error = True

        elif "expression" in licdata:
            if expr := licdata.get("expression"):
                collection.append({"spdx-expression": expr})
            else:
                error = True

        else:
            error = True

        if error:
            logging.error(
                "No expected license information found under 'licenses' key in SBOM: %s",
                licdata,
            )

    simplified_license_data = _unify_licenses_data(collection, use_flict=use_flict)
    return _license_short_to_valid_cdx_item(simplified_license_data)


def extract_items_from_component(component: dict, items: list, use_flict: bool) -> dict:
    """Extract certain items from a single component of a CycloneDX SBOM"""
    # Very noisy logging, disabled
    # logging.debug(
    #     "Handling component: purl = %s, name = %s", component.get("purl"), component.get("name")
    # )
    extraction = {}
    # Loop requested data points for extraction
    for item in items:
        # `licenses-short` is a custom data point that creates a licenses
        # output that is easier to parse later
        if item == "licenses-short":
            extraction[item] = _shorten_cdx_licenses_item(
                component.get("licenses", []), use_flict=use_flict
            )

        # For all other fields, just return the output
        else:
            extraction[item] = component.get(item, None)

    return extraction


def licenses_short_to_string(licenses: list) -> str:
    """
    Convert the shortened SBOM licenses output (created by passing
    `licenses-short` to `extract_items_from_component()`) to a single license
    expression/name.
    """
    if licenses:
        licshort: dict = licenses[0]
        if expr := licshort.get("expression"):
            return expr
        if name := licshort.get("license", {}).get("name", ""):
            return name

    return ""


def spdx_expression_to_cdx_licenses(spdx_expression: str) -> list:
    """
    Convert a SPDX expression to a valid CycloneDX licenses item
    """
    return [{"expression": spdx_expression}]


def extract_items_from_cdx_sbom(
    sbom_path: str, information: list, use_flict: bool = True
) -> list[dict]:
    """Extract certain items from all components of a CycloneDX SBOM (JSON)"""
    sbom = read_json_file(sbom_path)

    result = []
    # Loop all contained components
    for comp in sbom.get("components", []):
        result.append(extract_items_from_component(comp, information, use_flict))

    return result
