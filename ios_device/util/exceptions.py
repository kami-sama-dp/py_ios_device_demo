
class PyPodException(Exception):
    pass


class MuxError(PyPodException):
    pass


class MuxVersionError(MuxError):
    pass
