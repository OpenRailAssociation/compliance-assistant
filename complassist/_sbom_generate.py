# SPDX-FileCopyrightText: 2024 DB Systel GmbH
#
# SPDX-License-Identifier: Apache-2.0

"""Create a CycloneDX SBOM using cgxgen as Docker container"""

import logging
import re
import subprocess
import sys
from os.path import abspath, basename, dirname
from shutil import copy2
from tempfile import NamedTemporaryFile, gettempdir
from typing import Literal
from uuid import uuid4

import docker
from docker.errors import APIError, ContainerError, DockerException, ImageNotFound

from ._helpers import print_json_file


def _sanitize_container_name(name: str) -> str:
    """
    Sanitizes a Docker container name to conform to Docker's naming rules.

    Args:
        name (str): The initial container name, potentially containing invalid
        characters.

    Returns:
        str: The sanitized container name, with spaces replaced and disallowed
        characters removed.
    """
    # Remove spaces
    name = name.replace(" ", "_")
    # Remove all disallowed characters
    name = re.sub("[^a-zA-Z0-9_.-]+", "_", name)
    # Fix first character when it's not allowed, and return
    return re.sub("^[^a-zA-Z0-9]+", "0", name)


def _run_cdxgen_docker(
    dclient: docker.DockerClient,
    directory: str,
    cont_name: str,
    output_path: str,
    image: str = "ghcr.io/cyclonedx/cdxgen",
) -> None:
    """
    Runs a Docker container using the specified cdxgen image to generate a SBOM
    for the provided directory.

    Args:
        dclient (docker.DockerClient): The Docker client used to interact with
        the Docker service.

        directory (str): The path to the project directory for which the SBOM is
        to be generated.

        cont_name (str): The name assigned to the Docker container.

        output_path (str): The file path where the generated SBOM will be saved
        on the local system.

        image (str, optional): The Docker image to use for generating the SBOM.
        Defaults to `ghcr.io/cyclonedx/cdxgen`.

    Raises:
        SystemExit: If the Docker container fails to start, the image is not
        found, or there is a Docker API error.
    """
    logging.debug(
        "Running image '%s' on directory '%s' with name '%s' and output '%s'",
        image,
        directory,
        cont_name,
        output_path,
    )
    try:
        dclient.containers.run(
            image=image,
            name=cont_name,
            remove=True,
            volumes=[f"{directory}:/app", f"{dirname(output_path)}:/sbom_data"],
            tty=True,
            command=["-r", "/app", "-o", f"/sbom_data/{basename(output_path)}"],
        )
    except ContainerError as err:
        logging.critical("Docker container wasn't able to start: %s", err)
        sys.exit(1)
    except ImageNotFound as err:
        logging.critical("Docker image not found: %s", err)
        sys.exit(1)
    except APIError as err:
        logging.critical("Docker API error: %s", err)
        sys.exit(1)


def sbom_gen_cdxgen_docker(directory: str, output: str = "") -> str:
    """
    Generates a CycloneDX Software Bill of Materials (SBOM) for the project
    located in the specified directory.

    This function uses the Docker `cdxgen` image, a tool for generating SBOMs,
    inside a container. The resulting SBOM is saved as a JSON file and its path
    is returned.

    Args:
        directory (str): The path to the directory containing the project for
        which the SBOM is to be generated. The path can be either relative or
        absolute.

        output (str): The path to the SBOM that is to be generated. If left
        empty, it will be created in a temporary directory.

    Returns:
        str: The absolute path to the generated SBOM JSON file.

    Raises:
        SystemExit: If the Docker daemon is not available or cannot be reached,
        the function logs a critical error message and exits the program with
        status code 1.

    Dependencies:
        - Docker: The function interacts with Docker to create and manage
          containers.
    """
    # Initiate Docker client
    try:
        dclient = docker.from_env()
    except DockerException as err_daemon:
        logging.critical("Docker daemon does not seem to be available: %s", err_daemon)
        sys.exit(1)

    # Turn directory into absolute path, to support directories like `.`
    directory = str(abspath(directory))
    # Define names for container and SBOM output
    cont_name = _sanitize_container_name(f"{basename(directory)}_{uuid4().hex[:6]}")
    # Define output path
    if not output:
        output = f"{gettempdir()}/{cont_name}.json"

    # Create SBOM in temporary file. This enables the program to delete the SBOM
    # generated by cdxgen under root ownership
    logging.info("Generating SBOM for %s using cdxgen", directory)
    with NamedTemporaryFile() as tmpfile:
        _run_cdxgen_docker(dclient, directory, cont_name, tmpfile.name)

        # Copy to final destination with user permissions, or print file if requested
        if output == "-":
            print_json_file(tmpfile.name)
        else:
            copy2(tmpfile.name, output)

            logging.info("SBOM has been saved to %s", output)

    return output


def _run_program(program: str, *arguments) -> tuple[int, str, str]:
    cmd = [program, *arguments]
    logging.debug("Running %s", cmd)
    try:
        ret = subprocess.run(cmd, capture_output=True, check=False)
    except FileNotFoundError as exc:
        logging.critical(
            "There was an error executing '%s'. The file does not seem to exist: %s", program, exc
        )
        sys.exit(1)
    code = ret.returncode
    stderr = ret.stderr.decode("UTF-8").strip()
    stdout = ret.stdout.decode("UTF-8").strip()

    return code, stdout, stderr


def _run_syft(directory: str, tmpfile: str) -> tuple[int, str, str]:
    """Run syft scan to generate SBOM"""
    _, syft_version, _ = _run_program("syft", "--version")
    logging.info("Running %s to generate SBOM", syft_version)
    return _run_program("syft", "scan", f"dir:{directory}", "-o", f"cyclonedx-json={tmpfile}")


def _run_cdxgen(directory: str, tmpfile: str) -> tuple[int, str, str]:
    """Run cdxgen to generate SBOM"""
    _, cdxgen_version, _ = _run_program("cdxgen", "--version")
    logging.info("Running cdxgen %s to generate SBOM", cdxgen_version)
    return _run_program("cdxgen", "-r", "-o", tmpfile)


def sbom_gen_system_program(
    program: Literal["syft", "cdxgen"], directory: str, output: str = ""
) -> str:
    """
    Generates a CycloneDX Software Bill of Materials (SBOM) for the project
    located in the specified directory.

    This function can use multiple applications, e.g. syft and cdxgen, as
    installed on the system. The resulting SBOM is saved as a JSON file and its
    path is returned.

    Args:
        program (str): The program which shall be used for SBOM generation.
        Supported choices are provided in the type hinting.

        directory (str): The path to the directory containing the project for
        which the SBOM is to be generated. The path can be either relative or
        absolute.

        output (str): The path to the SBOM that is to be generated. If left
        empty, it will be created in a temporary directory.

    Returns:
        str: The absolute path to the generated SBOM JSON file.
    """

    with NamedTemporaryFile() as tmpfile:
        if program == "syft":
            code, stdout, stderr = _run_syft(directory=directory, tmpfile=tmpfile.name)
        elif program == "cdxgen":
            code, stdout, stderr = _run_cdxgen(directory=directory, tmpfile=tmpfile.name)
        else:
            logging.critical("Unsupported program provided for SBOM generation")
            sys.exit(1)

        if code != 0:
            logging.critical("There was an error during SBOM generation: %s\n%s", stdout, stderr)
            sys.exit(1)

        # Print file and exit if output is set to `-`
        if output == "-":
            print_json_file(tmpfile.name)
            return "-"

        # Set an output file in a temp location, if none given
        if not output:
            output = f"{gettempdir()}/sbom-{basename(tmpfile.name)}.json"

        # Copy temporary SBOM file to final destination
        try:
            copy2(tmpfile.name, output)
        except FileNotFoundError:
            logging.critical(
                "Could not copy the temporary SBOM from '%s' to '%s'. "
                "Path does not seem to exist or be accessible.",
                tmpfile.name,
                output,
            )
            sys.exit(1)
        except PermissionError:
            logging.critical(
                "Could not copy the temporary SBOM from '%s' to '%s'. User has no permission.",
                tmpfile.name,
                output,
            )
            sys.exit(1)

        logging.info("SBOM has been saved to %s", output)

    return output
