# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Functions concerning working with ClearlyDefined"""

import logging
import sys
from os.path import join as pathjoin
from urllib.parse import urljoin

from packageurl import PackageURL
from requests.exceptions import JSONDecodeError

from ._helpers import make_request_with_retry, replacer


def purl_to_cd_coordinates(purl: str) -> str:
    """
    Converts a Package URL (purl) to ClearlyDefined coordinates.

    Parses the purl and translates it into a coordinate format compatible with
    ClearlyDefined, handling necessary type conversions and provider mappings.

    Args:
        purl (str): The Package URL to be converted.

    Returns:
        str: The ClearlyDefined coordinates derived from the purl.

    Raises:
        SystemExit: If the provided purl is not valid, the function logs a
        critical error and exits.
    """
    try:
        purl_obj = PackageURL.from_string(purl)
    except ValueError as exc:
        logging.critical("Package URL '%s' does not seem to be a valid purl: %s", purl, exc)
        sys.exit(1)

    logging.debug("purl string '%s' converted to purl object '%s'", purl, repr(purl_obj))

    # Convert to dict, replacing empty values with "-"
    p = purl_obj.to_dict(empty="-")

    # Fix types that are different in purl and CD
    type_fix = {"cargo": "crate", "github": "git"}

    coordinates: dict = {
        "type": replacer(p.get("type", ""), type_fix),
        "provider": "",
        "namespace": p.get("namespace"),
        "name": p.get("name"),
        "version": p.get("version"),
    }

    # Update coordinates with provider, based on type
    type_to_provider = {
        "crate": "cratesio",
        "git": "github",
        "maven": "mavencentral",
        "npm": "npmjs",
        "pypi": "pypi",
    }
    coordinates["provider"] = replacer(coordinates["type"], type_to_provider)

    return "/".join([v for _, v in coordinates.items()])


def _cdapi_call(
    path: str,
    method: str = "GET",
    api_url: str = "https://api.clearlydefined.io",
    basepath: str = "definitions",
    json_dict: dict | list | None = None,
    **params: str,
) -> dict:
    """
    Makes a request to the ClearlyDefined API.

    Constructs and sends a request to the ClearlyDefined API, either with query
    parameters or a JSON payload, and returns the JSON response if available.

    Args:
        path (str): The API endpoint path relative to the basepath.

        method (str, optional): The HTTP method to use for the request (e.g.,
        "GET", "POST"). Defaults to "GET".

        api_url (str, optional): The base URL of the ClearlyDefined API.
        Defaults to "https://api.clearlydefined.io".

        basepath (str, optional): The base path for the API endpoint. Defaults
        to "definitions".

        json_dict (dict | None, optional): A dictionary to be sent as a JSON
        payload in the request body. Defaults to None.

        **params (str): Additional query parameters to include in the request.

    Returns:
        dict: The JSON response from the API, or a dictionary containing the
        response text if JSON decoding fails.
    """
    url = urljoin(api_url, pathjoin(basepath, path))
    if json_dict:
        result = make_request_with_retry(method=method, url=url, json=json_dict, params=params)
    else:
        result = make_request_with_retry(method=method, url=url, params=params)

    # Return JSON response if possible
    try:
        return result.json()
    except JSONDecodeError:
        logging.debug("JSON return is no valid JSON")
        return {"result": result.text}
    except AttributeError:
        logging.warning("API call did not return a valid response. No ClearlyDefined returned")
        return {"result": "error"}


def _extract_license_copyright(cd_api_response: dict) -> tuple[str, str]:
    """
    Extracts the declared license and detected copyright attributions from a
    ClearlyDefined API response.

    Args:
        cd_api_response (dict): The JSON response from the ClearlyDefined API.

    Returns:
        tuple[str, str]: A tuple containing:
            - The declared license as a string, or an empty string if not found.
            - The detected copyright attributions as a single string, with each
              attribution separated by a newline, or an empty string if not
              found.
    """
    package_name = cd_api_response.get("coordinates", {}).get("name", "")
    license_declared = ""
    copyrights: list[str] = []
    if licensed := cd_api_response.get("licensed"):
        # Get license
        license_declared = licensed.get("declared", "")

        # Get copyright attributions
        if facets := licensed.get("facets"):
            try:
                copyrights = facets.get("core", {}).get("attribution", {}).get("parties", [])
            except (TypeError, AttributeError):
                pass

    if not license_declared:
        logging.debug("No results for declared license from ClearlyDefined for %s", package_name)
    if not copyrights:
        logging.debug(
            "No results for copyright attributions from ClearlyDefined for %s", package_name
        )

    return license_declared, "\n".join(copyrights).strip()


def _send_cd_harvest_request(coordinates: str) -> None:
    """
    Sends a harvest request to ClearlyDefined for the given coordinates.

    Triggers a ClearlyDefined harvest operation for the provided coordinates to
    request the collection of metadata and license information.

    Args:
        coordinates (str): The ClearlyDefined coordinates or Package URL (purl)
        for which to request harvesting.
    """
    _cdapi_call(
        path="",
        method="POST",
        basepath="harvest",
        json_dict={"tool": "package", "coordinates": coordinates},
    )


def get_clearlydefined_license_and_copyright(coordinates: str) -> tuple[str, str]:
    """
    Retrieves the declared license for the specified coordinates from
    ClearlyDefined.

    Queries the ClearlyDefined API to get the declared license for the provided
    coordinates or Package URL (purl). If no license is found, it initiates a
    harvest request.

    Args:
        coordinates (str): The ClearlyDefined coordinates or Package URL for
        which to retrieve the license.

    Returns:
        tuple[str, str]: A tuple containing:
            - The declared license as a string, or an empty string if not found.
            - The detected copyright attributions as a single string, with each
              attribution separated by a newline, or an empty string if not
              found.
    """
    api_return = _cdapi_call(coordinates, expand="-files")

    declared_license, copyrights = _extract_license_copyright(api_return)

    # Declared license couldn't be extracted. Add to harvest
    if not declared_license:
        logging.info(
            "Adding %s to be harvest by ClearlyDefined. "
            "Make sure the package and this version actually exists, and try again later.",
            coordinates,
        )
        _send_cd_harvest_request(coordinates)

    return declared_license, copyrights


def get_clearlydefined_license_and_copyright_in_batches(
    purls: list[str],
) -> dict[str, tuple[str, str]]:
    """
    Retrieves the declared license for multiple purls from
    ClearlyDefined.

    Queries the ClearlyDefined API to get the declared license for the provided
    packages via Package URLs. If no license is found, it initiates a
    harvest request.

    Args:
        coordinates (str): The ClearlyDefined coordinates or Package URL for
        which to retrieve the license.

    Returns:
        tuple[str, str]: A tuple containing:
            - The declared license as a string, or an empty string if not found.
            - The detected copyright attributions as a single string, with each
              attribution separated by a newline, or an empty string if not
              found.
    """
    coordinates_purls = {purl_to_cd_coordinates(purl): purl for purl in purls}
    api_return = _cdapi_call(
        path="", method="POST", json_dict=list(coordinates_purls.keys()), expand="-files"
    )

    result: dict[str, tuple[str, str]] = {}
    for pkg_coordinates, cd_data in api_return.items():
        pkg_purl = coordinates_purls[pkg_coordinates]
        declared_license, copyrights = _extract_license_copyright(cd_data)

        # Declared license couldn't be extracted. Add to harvest
        if not declared_license:
            logging.info(
                "Adding %s to be harvest by ClearlyDefined. "
                "Make sure the package and this version actually exists, and try again later.",
                pkg_coordinates,
            )
            _send_cd_harvest_request(pkg_coordinates)

        result[pkg_purl] = (declared_license, copyrights)

    return result


def print_clearlydefined_result(results: tuple[str, str]) -> None:
    """
    Pretty-print the results for declared license and copyright attributions
    retrieved from the ClearlyDefined API for a package.

    Args:
        results (tuple[str, str]): A tuple containing:
            - The declared license as a string, or an empty string if not found.
            - The detected copyright attributions as a single string, with each
              attribution separated by a newline, or an empty string if not
              found.

    Returns:
        str: A pretty-printed, human-readable output of both data points
    """
    output = f"Declared license: {results[0]}\n\n"
    output += "Detected copyright attributions:"
    if attribs := results[1]:
        output += f"\n{attribs}"

    print(output)
