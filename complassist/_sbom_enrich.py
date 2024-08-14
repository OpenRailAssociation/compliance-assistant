# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Generate a CycloneDX SBOM and enrich its licensing data via ClearlyDefined"""

import logging
from datetime import datetime

from . import __version__
from ._clearlydefined import (
    get_clearlydefined_license_and_copyright,
    get_clearlydefined_license_and_copyright_in_batches,
    purl_to_cd_coordinates,
)
from ._helpers import extract_excerpt, read_json_file, write_json_file
from ._sbom_parse import (
    extract_items_from_cdx_sbom,
    extract_items_from_component,
    licenses_short_to_string,
    spdx_expression_to_cdx_licenses,
)


def _compare_sbom_cd_license(
    component: dict,
    cd_license: str | None,
    sbom_license: str,
    sbom_licenses_item: list[dict],
    sbom_licenses_short_item: list[dict],
) -> tuple[str, str]:
    """
    Compares and potentially updates the SBOM component's license information
    with data from ClearlyDefined.

    If the license from ClearlyDefined is valid and differs from the SBOM
    license, it updates the SBOM component's license with the ClearlyDefined
    license. If the ClearlyDefined data is not helpful, it checks if the SBOM's
    simplified license data should be used instead.

    Args:
        component (dict): The component data from the SBOM to be enriched.

        cd_license (str): The license expression from ClearlyDefined.

        sbom_license (str): The current license expression/name in the SBOM.

        sbom_licenses_item (list[dict]): The original licenses item in the SBOM.

        sbom_licenses_short_item (list[dict]): The simplified or shortened
        licenses item.

    Returns:
        tuple[str, str]: A tuple containing:
            - A message indicating the action taken regarding the license update.
            - Logging level of the message.
    """
    msg, msg_level = "", "DEBUG"

    # If ClearlyDefined licensing data is helpful, assume it's better than the SBOM's
    if cd_license not in ("NOASSERTION", "", None):
        # Update the licenses item in the CycloneDX SBOM if ClearlyDefined
        # has helpful data
        if sbom_license != cd_license:
            msg = f"Updating license: '{sbom_license}' -> '{cd_license}'"
            # Only report as INFO if there was a license in the SBOM before
            if sbom_license:
                msg_level = "INFO"
            component["licenses"] = spdx_expression_to_cdx_licenses(cd_license)
        else:
            msg = "License data in SBOM is same as at ClearlyDefined"

    # Otherwise, stick with data from SBOM. Update it with shorter/simplified string
    else:
        # Compare SBOM licenses data with shorted licenses data. Update, if differs
        if sbom_licenses_item != sbom_licenses_short_item:
            msg = (
                "ClearlyDefined does not provide helpful licensing data, "
                "but the SBOM licenses data has been shortened/simplified"
            )
            component["licenses"] = sbom_licenses_short_item

        msg = (
            "ClearlyDefined does not provide helpful licensing data, SBOM data will not be updated"
        )

    return msg, msg_level


def _compare_sbom_cd_copyright(
    component: dict, cd_copyright: str | None, sbom_copyright: str
) -> tuple[str, str]:
    """
    Compares and potentially updates the SBOM component's copyright information
    with data from ClearlyDefined.

    If the copyright information from ClearlyDefined is valid and differs from
    the SBOM copyright, it updates the SBOM component's copyright with the
    ClearlyDefined data. If the ClearlyDefined data is not helpful, it retains
    the SBOM's existing copyright data.

    Args:
        component (dict): The component data from the SBOM to be enriched.
        cd_copyright (str): The copyright string from ClearlyDefined.
        sbom_copyright (str): The current copyright item in the SBOM.

    Returns:
        Returns:
        tuple[str, str]: A tuple containing:
            - A message indicating the action taken regarding the copyright update.
            - Logging level of the message.
    """
    msg, msg_level = "", "DEBUG"

    if cd_copyright not in ("", None):
        # Update the copyright item in the CycloneDX SBOM if ClearlyDefined
        # has helpful data
        if sbom_copyright != cd_copyright:
            msg = (
                "Updating copyright: "
                f"'{extract_excerpt(sbom_copyright)}' -> '{extract_excerpt(cd_copyright)}'"
            )
            # Only report as INFO if there was a copyright in the SBOM before
            if sbom_copyright:
                msg_level = "INFO"
            component["copyright"] = cd_copyright
        else:
            msg = "Copyright data in SBOM is same as at ClearlyDefined"
    else:
        msg = (
            "ClearlyDefined does not provide helpful copyright data, SBOM data will not be updated"
        )

    return msg, msg_level


def _enrich_component_with_cd_data(
    component: dict, clearlydefined_data: dict[str, dict[str, str]]
) -> None:
    """
    Enriches a single component with data from ClearlyDefined.

    Args:
        component (dict): The component data to enrich.

        clearlydefined_data (dict): Previously fetched data for detected PURLs
        from ClearlyDefined.
    """
    # Get purl, original licenses, and short/simplified licenses data from component
    raw_data = extract_items_from_component(
        component, ["purl", "licenses", "licenses-short", "copyright"], use_flict=True
    )
    # Put raw data into separate variables, slightly adapted
    purl = raw_data["purl"]
    sbom_licenses_item: list[dict] = raw_data["licenses"]
    sbom_licenses_short_item: list[dict] = raw_data["licenses-short"]
    sbom_license = licenses_short_to_string(sbom_licenses_short_item)
    sbom_copyright = raw_data["copyright"]

    # Get fetched licensing/copyright data from ClearlyDefined
    cd_license = clearlydefined_data[purl].get("license")
    cd_copyright = clearlydefined_data[purl].get("copyright")

    # Compare license data of SBOM with ClearlyDefined
    msg, msg_level = _compare_sbom_cd_license(
        component, cd_license, sbom_license, sbom_licenses_item, sbom_licenses_short_item
    )
    if msg_level == "INFO":
        logging.info("[%s] %s", purl, msg)
    else:
        logging.debug("[%s] %s", purl, msg)

    # Compare cpyright data of SBOM with ClearlyDefined
    msg, msg_level = _compare_sbom_cd_copyright(component, cd_copyright, sbom_copyright)
    if msg_level == "INFO":
        logging.info("[%s] %s", purl, msg)
    else:
        logging.debug("[%s] %s", purl, msg)


def _update_sbom_metadata(sbom: dict) -> dict:
    """
    Updates the Software Bill of Materials (SBOM) with additional metadata.

    This function updates the SBOM dictionary by incrementing its version,
    adding a current timestamp, and appending metadata about the tool used for
    compliance assistance. If necessary, it creates missing sections in the
    SBOM metadata.

    Args:
        sbom (dict): The SBOM dictionary to be updated.

    Returns:
        dict: The updated SBOM dictionary with the new metadata values.
    """

    # Prepare new/additional metadata values
    version = int(sbom.get("version", 1)) + 1
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    tool = {
        "name": "compliance-assistant",
        "group": "OpenRailAssociation",
        "version": __version__,
        "purl": f"pkg:pypi/compliance-assistant@{__version__}",
        "bom-ref": f"pkg:pypi/compliance-assistant@{__version__}",
        "type": "application",
        "author": "OpenRail Association",
        "publisher": "OpenRail Association",
    }
    author = {
        "name": "compliance-assistant by OpenRail Association",
    }

    # Set new version
    sbom["version"] = version
    # Add timestamp (and metadata if missing)
    try:
        sbom["metadata"]["timestamp"] = timestamp
    except KeyError:
        sbom["metadata"] = {"timestamp": timestamp}
    # Add tool component
    try:
        sbom["metadata"]["tools"]["components"].append(tool)
    except KeyError:
        if "tools" not in sbom["metadata"]:
            sbom["metadata"]["tools"] = {}
            sbom["metadata"]["tools"]["components"] = [tool]
    # Add author
    try:
        sbom["metadata"]["authors"].append(author)
    except KeyError:
        sbom["metadata"]["authors"] = [author]

    return sbom


def enrich_sbom_with_clearlydefined(
    sbom_file: str, output_file: str, in_batches: bool = True
) -> None:
    """
    Parse a SBOM and enrich license/copyright data of each component with
    ClearlyDefined. Write result to new SBOM file.

    1. Read SBOM file
    2. For each component:
        1. Get its purl
        2. Get current licensing data, simplify it with flict
        3. Get licensing data from ClearlyDefined
        4. Compare both. If it differs, inform and update dict
    3. Update SBOM

    Args:
        sbom_file (str): Path to the input SBOM file.
        output_file (str): Path to save the enriched SBOM.
        in_batches (bool): Ask ClearlyDefined API for multiple packages at once.
    """

    sbom: dict[str, list[dict]] = read_json_file(sbom_file)

    # Loop all contained components, and collect ClearlyDefined data
    clearlydefined_data: dict[str, dict[str, str]] = {}
    all_purls: list[str] = [
        c["purl"] for c in extract_items_from_cdx_sbom(sbom_file, information=["purl"])
    ]
    if in_batches:

        # Split all purls in batches of `max_components` size
        max_components = 10
        purls_batches: list[list[str]] = [
            all_purls[x : x + max_components] for x in range(0, len(all_purls), max_components)
        ]
        for batch in purls_batches:
            logging.info("Getting ClearlyDefined data for %s", ", ".join(batch))
            result = get_clearlydefined_license_and_copyright_in_batches(batch)
            # Unpack result batches, and add to clearlydefined_data
            for purl, (cd_license, cd_copyright) in result.items():
                clearlydefined_data[purl] = {"license": cd_license, "copyright": cd_copyright}

    else:
        for purl in all_purls:
            logging.info("Getting ClearlyDefined data for %s", purl)
            cd_license, cd_copyright = get_clearlydefined_license_and_copyright(
                coordinates=purl_to_cd_coordinates(purl)
            )
            clearlydefined_data[purl] = {"license": cd_license, "copyright": cd_copyright}

    # Now, update the components with the fetched ClearlyDefined data
    for component in sbom.get("components", []):
        _enrich_component_with_cd_data(component, clearlydefined_data)

    # Update SBOM metadata
    sbom = _update_sbom_metadata(sbom)

    write_json_file(sbom, output_file)
