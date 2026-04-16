# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Logging functions."""

import http.client as http_client
import logging
from argparse import Namespace


def configure_logger(args: Namespace) -> logging.Logger:
    """Set logging options."""
    # Base logger config
    log = logging.getLogger()
    logging.basicConfig(
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
        http_client.HTTPConnection.debuglevel = 1

    return log
