class Error(Exception):
    pass


class ReferenceNotFoundError(Error):
    pass


class InvalidDatabaseError(Error):
    pass


class UnmappedPageError(Error):
    pass
