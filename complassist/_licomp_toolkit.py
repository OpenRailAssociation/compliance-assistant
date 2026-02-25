# SPDX-FileCopyrightText: 2024 DB Systel GmbH
# SPDX-FileCopyrightText: 2025 Henrik Sandklef <hesa@sandklef.com>
#
# SPDX-License-Identifier: Apache-2.0

"""Wrapper for some licomp-toolkit operations"""

import logging

from licomp_toolkit.format import LicompToolkitFormatter
from licomp_toolkit.toolkit import LicompToolkit
from licomp_toolkit.suggester import OutboundSuggester



# Since licomp-toolkit takes license usage scenarios into consideration
# some context about your dependencis is needed
# 'library' - using your dependencies as libraries (not tool, compiler, test, documentation...)
# 'binary-distribution' - provide your software to your users by distributing a binary
# ['licomp_reclicense'] - only use licomp-reclicense (the main licomp resource for the above context)

USECASE = 'library'
PROVISIONING = 'binary-distribution'
RESOURCES = ['licomp_reclicense']


def _format(output_format: str):
    return {'plain': 'text'}.get(output_format, 'json')

def licomp_toolkit_simplify_license(expression: str, output_format: str, no_relicensing: bool = True) -> str:
    """Simplify a license expression using licomp-toolkit"""
    options = ["-of", output_format]
    licomp_toolkit = LicompToolkit()
    simplified = licomp_toolkit.simplify(expression)
    logging.debug("Simplified '%s' to '%s' using licomp-toolkit", expression, simplified)
    return simplified


def licomp_toolkit_simplify_license_list(expressions: list[str]) -> list[str]:
    """Simplify a list of license expressions"""
    licomp_toolkit = LicompToolkit()
    simplified = [licomp_toolkit.simplify(lic) for lic in expressions]
    return list(set(simplified))


def licomp_toolkit_outbound_candidate(expression: str, output_format: str) -> str:
    """Get possible outbound license candidates using licomp-toolkit"""
    suggester = OutboundSuggester()
    licomp_toolkit = LicompToolkit()
    licenses_to_check = licomp_toolkit.supported_licenses()
    outbound_candidates = suggester.compat_licenses(expression,
                                                    USECASE,
                                                    PROVISIONING,
                                                    licenses_to_check,
                                                    RESOURCES)
    formatter = LicompToolkitFormatter.formatter(_format(output_format))
    formatted_candidates = formatter.format_licomp_licenses(outbound_candidates)
    return formatted_candidates

