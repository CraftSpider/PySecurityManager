
import secman as sec
import types

manager = sec.SecurityManager()  # Add `verbose=True` to see logs of all permissions
manager.set_permission(sec.Permission("import", True))
manager.set_permission(sec.Permission("exec", True))
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


# Many possible examples not included here. You can even block adding more audit hooks!
