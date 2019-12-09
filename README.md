
# Python Security Manager

A security manager, inspired by the Java Security Manager and [PEP 578](https://www.python.org/dev/peps/pep-0578/).
Designed to be simple to use, simply import and setup a manager.

## Usage

A simple manager, installed for all threads:

```py
import secman
manager = secman.SecurityManager()
# Allow imports of modules, not packaged (packages also require open and os.listdir)
manager.set_permission(secman.Permission("import", True))
manager.set_permission(secman.Permission("exec", True))
# By default, adds for all threads. Accepts a thread ID as a second value
secman.add_manager(manager)
```

By default, this manager cannot be removed, and no more can be added. As currently managers block
everything by default, and the secman package raises its own audits on manager and permission alteration.

## How It Works

### Setup
On import, the security manager sets up its classes/functions, and then runs a couple lines of code.
It installs a new audit hook, steals some references to various items, then deletes those items
from the public scope.

### Runtime
While running, the audit hook receives all audit events and associated arguments. Each time, the hook
checks the current thread ID, checks if any Managers exist for all threads or the current thread, then
dispatches to them if they're set. If their check is False, or they raise any Error, the hook raises
a SecurityError, which is propagated by the Python Interpreter to the calling scope.

### Shutdown
On shutdown, the interpreter will clear all hooks. By default, the Manager will raise a SecurityError
when this happens, to guarantee the shutdown of the runtime after hooks are cleared. This is done
because while the hook clear is unstoppable, this prevents malicious C code from calling the clear
without the user noticing.

## TODO

- Change to C, as the 'steal then delete' currently can be gotten around
- Finish 'Targets' to allow more extensive permissions
- Make more sane default manager settings, to encourage drop-in use
