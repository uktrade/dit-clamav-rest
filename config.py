import os


class BaseConfig(object):
    DEBUG = False
    TESTING = False

    APPLICATION_USERS = os.environ.get("APPLICATION_USERS", {})
    SENTRY_DSN = os.environ.get("SENTRY_DSN", "")

    CLAMAV_TXT_URI = "current.cvd.clamav.net"

    CLAMD_HOST = "localhost"
    CLAMD_PORT = 3310
    HOST = "0.0.0.0"
    PORT = int(os.environ.get('PORT', '8090'))


class ProductionConfig(BaseConfig):
    CLAMD_HOST = os.environ.get("CLAMD_HOST", "clamav")


class CircleCiConfig(BaseConfig):
    CLAMD_HOST = "localhost"
    DEBUG = True
    TESTING = True
    # pwd: letmein
    APPLICATION_USERS = "app1::$pbkdf2-sha256$29000$LiWkFELo3TvHGANACAGAkA$Re51NLQNiCYy0UAdnFbNfLltFDmiJOOzqjMPFRVBgMM"


class LocalConfig(CircleCiConfig):
    pass


class TestConfig(BaseConfig):
    DEBUG = True
    TESTING = True

    # pwd: letmein
    APPLICATION_USERS = "app1::$pbkdf2-sha256$29000$LiWkFELo3TvHGANACAGAkA$Re51NLQNiCYy0UAdnFbNfLltFDmiJOOzqjMPFRVBgMM"

    CLAMD_HOST = "clamd"
