
class SecurityException(BaseException):
    pass


class ManagerException(SecurityException):
    pass


class PermissionsException(SecurityException):

    def __init__(self, audit):
        super().__init__(audit)
        self.audit = audit
