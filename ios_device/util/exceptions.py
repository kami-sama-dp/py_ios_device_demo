
class PyPodException(Exception):
    pass


class MuxError(PyPodException):
    pass


class MuxVersionError(MuxError):
    pass


class NoMuxDeviceFound(MuxError):
    pass