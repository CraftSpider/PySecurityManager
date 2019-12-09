"""
    A module that implements a Java Security Manager style system in Python, using 3.8 audit hooks

    - Managers can be registered globally or per-thread
    - Global managers take priority over thread managers
    - By default, no manager is registered
    - A manager cannot audit itself, all audits raised from inside an existing audit are automatically allowed to avoid
    stack overflow.
    - Secman itself raises audits on adding and removing managers, and any other important events
    - Fail secure: any unexpected errors result in a security failure

    Audits Sent:
    secman.add_manager
    secman.remove_manager
    secman.set_permission
    secman.get_permission

    TODO: Implement in C so it's truly secure, currently there are probably ways around it
"""

import sys
import threading

from . import manager, permissions, errors, targets
from .manager import *
from .permissions import *
from .errors import *
from .targets import *


__author__ = "CraftSpider"
__copyright__ = "Copyright 2019, CraftSpider"
__credits__ = ["CraftSpider"]

__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "CraftSpider"
__email__ = "runetynan@gmail.com"
__status__ = "Prototype"


def security_hook(name, *args):
    # Allow us to call _getframe
    if name == "sys._getframe":
        frame = args[0][0]
        if frame.f_code.co_filename == __file__:
            del frame
            return
    # Inspect the callstack, and protect from a recursive audit trail
    frame = sys._getframe(0)
    while frame.f_back != None:
        frame = frame.f_back
        if frame.f_code == security_hook.code:
            return
    del frame

    result = True  # Fail secure
    try:
        import threading
        managers = security_hook.managers
        tid = threading.current_thread().ident
        if -1 in managers:
            result = managers[-1].dispatch_audit(name, *args[0])
        if result:
            if tid in managers:
                result = managers[tid].dispatch_audit(name, *args[0])
    except BaseException as e:
        # This ensures that the traceback doesn't reveal anything about the Manager
        # Possibly over-paranoid, but also makes tracebacks look cleaner
        e.__traceback__ = None
        if isinstance(e, errors.SecurityException):
            raise e from None
        else:
            raise errors.ManagerException(
                f"Manager raised unexpected Exception {type(e).__name__} while handling audit {name}"
            ) from e
    if not result:
        raise errors.PermissionsException(name)


security_hook.managers = manager._managers
security_hook.code = security_hook.__code__
sys.addaudithook(security_hook)

del manager._managers
del threading
