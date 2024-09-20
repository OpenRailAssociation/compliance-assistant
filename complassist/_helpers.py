# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Overarching helper functions"""

import json
import logging
from pathlib import Path
from time import sleep

import requests


def dict_to_json(data: dict) -> str:
    """Convert a dict to pretty-printed JSON string"""
    return json.dumps(data, indent=2, sort_keys=False)


def replacer(string: str, replacement_dict: dict) -> str:
    """
    Replaces a string based on a replacement dictionary.

    If the string matches a key in the replacement dictionary, it is replaced by
    the corresponding value. If no match is found, the original string is
    returned.

    Args:
        string (str): The string to be checked and possibly replaced.
        replacement_dict (dict): A dictionary where keys are strings to be
        replaced and values are their replacements.

    Returns:
        str: The replaced string if a match is found, otherwise the original
        string.
    """
    if string in replacement_dict:
        replacement = replacement_dict.get(string, "")
        return replacement

    return string


def read_json_file(path: str) -> dict:
    """Open a JSON file and return it as dict"""
    with open(path, "r", encoding="UTF-8") as jsonfile:
        return json.load(jsonfile)


def write_json_file(data: dict, path: str) -> None:
    """Write a dict into a JSON file, unless path is `-` for which it will be stdout"""
    if path == "-":
        print(json.dumps(data, indent=2))
    else:
        with open(path, "w", encoding="UTF-8") as jsonfile:
            json.dump(data, jsonfile, indent=2)


def print_json_file(path: str) -> None:
    """Open a JSON file and print it to stdout"""
    write_json_file(read_json_file(path), "-")


def delete_file(path: str) -> None:
    """Delete a file"""
    Path(path).unlink(missing_ok=True)


def extract_excerpt(multiline_string: str | None, length: int = 50) -> str:
    """
    Extracts a one-line excerpt from a multiline string.

    Args:
        multiline_string (str): The input multiline string.
        length (int): The maximum length of the excerpt. Default is 50.

    Returns:
        str: A one-line excerpt with the specified length.
    """
    if multiline_string is None:
        multiline_string = ""

    # Combine lines into a single string, separating by space
    single_line = " ".join(multiline_string.split())

    # Return the excerpt, truncated to the specified length with ellipsis if needed
    return (single_line[:length] + "...") if len(single_line) > length else single_line


def make_request_with_retry(  # pylint: disable=inconsistent-return-statements
    method: str, url: str, retries: int = 3, wait: int = 20, **kwargs
) -> requests.Response:
    """
    Make an HTTP request with retry logic on timeout.

    Args:
        method (str): The HTTP method (e.g., 'GET', 'POST').
        url (str): The URL to make the request to.
        retries (int): The number of retry attempts (default is 3).
        wait (int): The wait time between retries in seconds (default is 20).
        **kwargs: Additional keyword arguments to pass to the `requests.request` method.

    Returns:
        requests.Response: The response object from the request.

    Raises:
        requests.exceptions.RequestException: If all retries fail, the last exception is raised.
    """
    for attempt in range(retries):
        try:
            response = requests.request(method=method, url=url, timeout=10, **kwargs)
            response.raise_for_status()  # Raise an exception for HTTP errors
            return response
        except requests.exceptions.Timeout:
            logging.warning(
                "Timeout on attempt %s/%s. Retrying in %s seconds...", attempt + 1, retries, wait
            )
            if attempt < retries - 1:
                sleep(wait)
            else:
                logging.error("All retry attempts failed due to timeout.")
        except requests.exceptions.RequestException as e:
            logging.error("Request failed: %s", e)

    return requests.Response()
