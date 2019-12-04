
import abc
import sys
from . import errors, permissions


__all__ = ["SecurityManagerBase", "SecurityManager", "add_manager", "remove_manager"]


_managers = {}


class SecurityManagerBase(abc.ABC):

    @abc.abstractmethod
    def set_permission(self, permission):
        raise NotImplementedError()

    @abc.abstractmethod
    def get_permission(self, audit):
        raise NotImplementedError()

    @abc.abstractmethod
    def is_allowed(self, audit, *args):
        raise NotImplementedError()

    @abc.abstractmethod
    def dispatch_audit(self, audit, *args):
        raise NotImplementedError()


class SecurityManager(SecurityManagerBase):

    def __init__(self, verbose=False):
        super().__init__()
        self.permissions = {}
        self.verbose = verbose

    def _find_hook(self, t):
        t = t.split(".")
        result = None
        for i in reversed(t):
            result = getattr(self, "on_" + i, None)
            if result is not None:
                break
        return result

    def _print_error(self, message):
        print(f"Error:\n\t{message}")

    def _get_permission(self, audit):
        perm = self.permissions.get(audit)
        if perm is None:
            perm = permissions.Permission(audit, False)
        return perm

    def _get_caller(self):
        try:
            return sys._getframe(4)
        except ValueError:
            return None

    def set_permission(self, permission):
        sys.audit("secman.set_permission", self, permission)
        self.permissions[permission.name] = permission

    def get_permission(self, audit):
        sys.audit("secman.get_permission", self, audit)
        return self._get_permission(audit)

    def is_allowed(self, audit, *args):
        try:
            return self.dispatch_audit(audit, *args)
        except errors.SecurityException:
            return False

    def dispatch_audit(self, audit, *args):
        perm = self._get_permission(audit)
        if perm is None:
            self._print_error(f"No permission found for {audit}")
            return False

        hook = self._find_hook(perm.type())
        if hook is None:
            self._print_error(f"No hook found for {audit}")
            return False

        try:
            return hook(perm, args)
        except BaseException as e:
            self._print_error(f"Uncaught exception in audit hook: {type(e).__name__} - {e}")
            raise

    def log(self, message):
        if self.verbose:
            print(message)

    def on_generic(self, perm, args):
        if perm.log:
            self.log(f"Generic Permission: {perm.name} {args}")
        return perm.allowed

    def on_security(self, perm, args):
        if perm.log:
            self.log(f"Security Permission: {perm.name} {args}")
        return perm.allowed

    def on_cpython(self, perm, args):
        if perm.log:
            self.log(f"Cpython Permission: {perm.name} {args}")
        return perm.allowed

    def on_io(self, perm, args):
        if perm.log:
            self.log(f"IO Permission: {perm.name} {args}")
        return perm.allowed

    def on_code(self, perm, args):
        if perm.log:
            self.log(f"Code Permission: {perm.name} {args}")
        return perm.allowed

    def on_ctypes(self, perm, args):
        if perm.log:
            self.log(f"Ctypes Permission: {perm.name} {args}")
        return perm.allowed

    def on_reflection(self, perm, args):
        if perm.log:
            self.log(f"Reflection Permission: {perm.name} {args}")
        return perm.allowed


def add_manager(manager, thread=-1):
    sys.audit("secman.add_manager", manager, thread)
    if not isinstance(manager, SecurityManagerBase):
        raise TypeError("Manager must be a subclass of SecurityManagerBase")
    managers = add_manager.managers
    if managers.get(thread) is not None:
        raise errors.ManagerException("Manager already registered for thread")
    managers[thread] = manager


def remove_manager(manager, thread=-1):
    sys.audit("secman.remove_manager", manager, thread)
    managers = remove_manager.managers
    if managers.get(thread) is None:
        raise errors.ManagerException("No manager registered for thread")
    if managers.get(thread) is not manager:
        raise errors.ManagerException("Manager on thread does not match passed manager")
    del managers[thread]


add_manager.managers = _managers
remove_manager.managers = _managers
