import dns.resolver
import logging
import sys

logger = logging.getLogger("CLAMAV-REST.VERSIONS_SERVICE")
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


class ClamAVLocalVersionService():
    def __init__(self, clamav):
        self._clamav =clamav

    def get_local_version_text(self):
        version = self._clamav.version()
        return version

    @staticmethod
    def parse_local_version(version_text):
        split = version_text.split('/')
        return split[1]


class ClamAVRemoteVersionService():

    def __init__(self, uri):
        self._uri = uri

    @staticmethod
    def parse_remote_version(version_text):
        split = version_text.split(':')
        return split[2]

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
