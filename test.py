
import secman as sec
import types

manager = sec.SecurityManager()  # Add `verbose=True` to see logs of all permissions
# Comment out to forbid import of modules
manager.set_permission(sec.Permission("import", True))
manager.set_permission(sec.Permission("exec", True))
# Comment out to forbid import of packages (above also required)
manager.set_permission(sec.Permission("open", True))
manager.set_permission(sec.Permission("os.listdir", True))
# Comment out to forbid ctypes
manager.set_permission(sec.Permission("ctypes.dlopen", True))
manager.set_permission(sec.Permission("ctypes.dlsym", True))
# Comment out to forbid exec/eval
manager.set_permission(sec.Permission("compile", True))
# Comment out to forbid code creation
manager.set_permission(sec.Permission("code.__new__", True))
# Comment out to forbid input
manager.set_permission(sec.Permission("builtins.input", True))
# Comment out to forbid object get/set
manager.set_permission(sec.Permission("object.__getattr__", True))
manager.set_permission(sec.Permission("object.__setattr__", True))
sec.add_manager(manager)

try:
    import gc
    import dbm
    print("Imported: ", gc, dbm)
except sec.PermissionsException as e:
    print("Exception:", type(e).__name__, e)

try:
    import ctypes
    result = ctypes.addressof(ctypes.c_float())
    print(result)
except sec.PermissionsException as e:
    print("Exception:", type(e).__name__, e)

try:
    exec("print('Exec Successful')")
except sec.PermissionsException as e:
    print("Exception:", type(e).__name__, e)
try:
    result = eval("1")
    print("Eval Result:", result)
except sec.PermissionsException as e:
    print("Exception:", type(e).__name__, e)

try:
    c = types.CodeType(0, 0, 0, 0, 0, 0, b"\x00\x00", (), (), (), "test.py", "test", 0, b"")
    print("Code Object:", c)
except sec.PermissionsException as e:
    print("Exception:", type(e).__name__, e)

try:
    result = input(">")
    print("Input Result:", result)
except sec.PermissionsException as e:
    print("Exception:", type(e).__name__, e)


def test(): ...


try:
    test.__code__ = test.__code__.replace(co_argcount=1, co_varnames=("test",))
    print("Function code changed")
except sec.PermissionsException as e:
    print("Exception:", type(e).__name__, e)


# Many possible examples not included here. You can even block adding more audit hooks!
