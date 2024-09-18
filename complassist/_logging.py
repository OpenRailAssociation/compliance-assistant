# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Logging functions"""
import logging


def configure_logger(args) -> logging.Logger:
    """Set logging options"""
    # Base logger config
    log = logging.getLogger()
    logging.basicConfig(
        encoding="utf-8",
        format="%(levelname)s: %(message)s",
        level=logging.INFO,
    )
    # Adapt logging level
    if getattr(args, "verbose", False):
        log.setLevel("DEBUG")
    # Activate extreme logging for requests to also get POST data
    if hasattr(args, "http_debug") and args.http_debug:
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        import http.client as http_client  # pylint: disable=import-outside-toplevel

        http_client.HTTPConnection.debuglevel = 1

    return log
