# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Wrapper for some flict operations"""

import logging
import subprocess


# We need to run flict as subprocess as usage as library is too complicated
def _run_flict(
    command: str, *arguments, options: list | None = None, warn_on_error: bool = True
) -> str:
    """
    Run flict with a command (e.g. 'verify') and a list of arguments
    (e.g. '-il', 'GPL-2.0-only', '-ol', 'MIT'), and a list of general options (e.g. ["-ip"])
    Return output as str
    """
    if options is None:
        options = []
    cmd = ["flict", *options, command, *arguments]
    ret = subprocess.run(cmd, capture_output=True, check=False)
    if ret.returncode != 0:
        if warn_on_error:
            logging.warning("flict exited with an error (%s): %s", ret.returncode, ret.stderr)

    return ret.stdout.decode("UTF-8").strip()


def flict_simplify(expression: str, output_format: str) -> str:
    """Simplify a license expression using flict"""
    return _run_flict("simplify", expression, options=["-of", output_format])
