"""Open Source License Compliance helpers"""

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

    return sorted(list(set(lic_expressions))), sorted(list(set(lic_names)))


def list_all_licenses(sbom_path: str, use_flict: bool = False) -> list[str]:
    """List all detected licenses of an SBOM, unified and sorted"""
    expressions, names = _extract_license_expression_and_names_from_sbom(sbom_path, use_flict)

    # Combine both lists, sort and unify again
    return sorted(list(set(expressions + names)))
