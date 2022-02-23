"""Clam AV version helpers

Inspired by https://forums.contribs.org/index.php?topic=49721.0
"""
import dns.resolver
import logging
import sys

logger = logging.getLogger("CLAMAV-REST.VERSIONS_SERVICE")


class VersionError(Exception):
    """Raised for version related errors."""


def parse_version(version_text, divider=":", offset=0):
    """Parse a version string.

    :param (str) version_text: Version text to parse.
    :param (str) divider: Divider token.
    :param (int) offset: Which slice.
    :returns (str): Sliced element.
    :raises: VersionError if text cannot be parsed.
    """
    if not version_text:
        raise VersionError("version_text is required")
    split = version_text.split(divider)
    try:
        return split[offset]
    except IndexError:
        raise VersionError(f"version_text does not contain {offset + 1} items")


def parse_local_version(version_text):
    """Parse remote version.

    Given something like 'ClamAV 0.100.3/25480/Fri Jun 14 08:12:45 2019'
    extract '25480'.

    :param (str) version_text: Remote version string.
    :returns (str): Extracted version.
    """
    return parse_version(version_text, '/', 1)


def parse_remote_version(version_text):
    """Parse remote version.

    Given something like '0.103.1:59:26120:1616678940:0:63:49191:333'
    extract '26120'.

    :param (str) version_text: Remote version string.
    :returns (str): Extracted version.
    """
    return parse_version(version_text, ':', 2)


def get_local_version_text(clamav):
    """Interrogate local clamd for version.

    :param (ClamdNetworkSocket) clamav: clamd connection.
    :returns (str): version string from clamd.
    :raises: VersionError if version cannot be acquired.
    """
    try:
        version = clamav.version()
    except Exception as e:
        msg = f"Failed to get local version info: {e}"
        logger.error(msg)
        raise VersionError(msg)
    else:
        logger.info(f"local version: {version}")
        return version


def get_remote_version_text(uri):
    """Get remote version info through a DNS lookup.

    :param (str) uri: Domain to perform lookup on.
    :returns (str): latest ClamAV version.
    """
    try:
        answers = dns.resolver.resolve(uri, "TXT")
    except Exception as e:
        msg = f"Failed to get remote version info: {e}"
        logger.error(msg)
        raise VersionError(msg)
    else:
        version = "unknown"
        for data in answers:
            for txt_string in data.strings:
                version = txt_string.decode("utf-8")
        logger.info(f"remote version: {version}")
        return version


def get_local_version_number(clamav):
    """Get the local Clam AV version.

    :param (ClamdNetworkSocket) clamav: clamd connection.
    :returns (str): Local Clam AV version.
    """
    return parse_local_version(get_local_version_text(clamav))


def get_remote_version_number(uri):
    """Get remote Clam AV version.

    :param (str) uri: Domain to use for version check.
    :returns (str): Latest ClamAV version.
    """
    return parse_remote_version(get_remote_version_text(uri))
