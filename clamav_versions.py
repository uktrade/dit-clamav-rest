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

    if len(split) < offset + 1:
        raise Exception("version_text does not contain %s items" % offset + 1)

    return split[offset]

class ClamAVLocalVersionService():
    def __init__(self, clamav):
        self._clamav = clamav

    @staticmethod
    def parse_local_version(version_text):
        return split_version(version_text, '/', 1)

    def get_local_version_text(self):
        try:
            version = self._clamav.version()
            return version
        except Exception as ex:
            logger.error(ex)
            raise ex


class ClamAVRemoteVersionService():
    def __init__(self, uri):
        self._uri = uri

    @staticmethod
    def parse_remote_version(version_text):
        return split_version(version_text, ':', 2)

    def get_remote_version_text(self):
        answers = dns.resolver.query(self._uri, "TXT")
        results = ""

        for data in answers:
            logger.info(data)
            logger.info(len(data.strings))

            for txt_string in data.strings:
                remote = txt_string.decode("utf-8")
                results = remote

        return results