# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Wrapper for some flict operations"""

import logging
import subprocess


# We need to run flict as subprocess as usage as library is too complicated
def _run_flict(
    command: str,
    *arguments,
    options: list | None = None,
    warn_on_error: bool = True,
) -> tuple[int, str, str]:
    """
    Run flict with a command (e.g. 'verify') and a list of arguments
    (e.g. '-il', 'GPL-2.0-only', '-ol', 'MIT'), and a list of general options (e.g. ["-ip"])
    Return: exit code, stdout, stderr
    """
    if options is None:
        options = []
    cmd = ["flict", *options, command, *arguments]
    logging.debug("Running flict: %s", cmd)
    ret = subprocess.run(cmd, capture_output=True, check=False)
    code = ret.returncode
    stderr = ret.stderr.decode("UTF-8").strip()
    stdout = ret.stdout.decode("UTF-8").strip()
    if code != 0:
        # If only warning requested, only log error, return normal output
        if warn_on_error:
            logging.warning(
                "flict exited with an error (%s): %s",
                code,
                stderr,
            )

    return code, stdout, stderr


def flict_simplify(expression: str, output_format: str, no_relicensing: bool = True) -> str:
    """Simplify a license expression using flict"""
    options = ["-of", output_format]
    if no_relicensing:
        options.append("-nr")
    _, simplified, _ = _run_flict("simplify", expression, options=options)

    logging.debug("Simplified '%s' to '%s' using flict", expression, simplified)

    return simplified


def flict_simplify_list(expressions: list[str]) -> list[str]:
    """Simplify a list of license expressions"""
    simplified = []
    for lic in expressions:
        simplified.append(flict_simplify(lic, output_format="text"))

    return list(set(simplified))


def flict_outbound_candidate(expression: str, output_format: str) -> str:
    """Get possible outbound license candidates using flict"""
    # TODO: `-el` would make this command more helpful but it has an error:
    # https://github.com/vinland-technology/flict/issues/391
    _, outbound_candidate, _ = _run_flict(
        "outbound-candidate", expression, options=["-nr", "-of", output_format]
    )
    return outbound_candidate
