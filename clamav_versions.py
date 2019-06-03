import dns.resolver
import logging
import sys

logger = logging.getLogger("CLAMAV-REST.VERSIONS_SERVICE")
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

'''
Kudos to https://forums.contribs.org/index.php?topic=49721.0 
'''


def split_version(version_text, divider, offset):
    if not version_text:
        raise Exception("version_text is required")

    split = version_text.split(divider)

    try:
        return split[offset]
    except IndexError:
        raise Exception("version_text does not contain %d items" % offset + 1)


def parse_local_version(version_text):
    return split_version(version_text, '/', 1)


def get_local_version_text(clamav):
    version = clamav.version()
    logger.info("local_version is %s" % version)
    return version

def get_local_version_number(clamav):
    text = get_local_version_text(clamav)
    if not text:
        raise BaseException(
                "local_version_text is empty - is clamav running")
    
    return parse_local_version(text)

def parse_remote_version(version_text):
    return split_version(version_text, ':', 2)

def get_remote_version_number(uri):
    text = get_remote_version_text(uri)
    return parse_remote_version(text)

def get_remote_version_text(uri):
    answers = dns.resolver.query(uri, "TXT")
    remote_version_text = ""

    for data in answers:
        for txt_string in data.strings:
            remote = txt_string.decode("utf-8")
            remote_version_text = remote

    logger.info("remote_version is %s" % remote_version_text)
    return remote_version_text
