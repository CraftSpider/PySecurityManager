
class Permission:

    def __new__(cls, name: str, allowed, *, target=None):
        if cls == Permission:
            if name.startswith("secman."):
                cls = SecurityPermission
            elif name in {"subprocess.Popen", "_winapi.CreateProcess"}:
                cls = ProcessPermission
            elif name in {"builtins.input"}:
                cls = IOPermission
            elif name.startswith("socket."):
                cls = SocketPermission
            elif name.startswith("mmap.") or name.startswith("glob.") or \
                    name.startswith("shutil.") or name.startswith("tempfile.") or \
                    name in {"open", "os.listdir", "os.scandir", "os.truncate"}:
                cls = FilePermission
            elif name in {"urllib.Request", "webbrowser.open"}:
                cls = NetworkPermission
            elif name.startswith("ftplib."):
                cls = FtpPermission
            elif name.startswith("telnetlib."):
                cls = TelnetPermission
            elif name.startswith("imaplib."):
                cls = ImapPermission
            elif name.startswith("poplib."):
                cls = PopPermission
            elif name.startswith("nntplib."):
                cls = NntpPermission
            elif name.startswith("smtplib."):
                cls = SmtpPermission
            elif name.startswith("sqlite3."):
                cls = Sqlite3Permission
            elif name in {"sys.addaudithook", "sys.excepthook"}:
                cls = MetaPermission
            elif name.startswith("object.") or name.startswith("sys.") or name in {"builtins.id", "os.system"}:
                cls = ReflectionPermission
            elif name.startswith("code.") or name in {"compile", "exec", "import"}:
                cls = CodePermission
            elif name in {"pdb.Pdb", "builtins.breakpoint"}:
                cls = DebugPermission
            elif name.startswith("array."):
                cls = NativePermission
            elif name.startswith("ctypes."):
                cls = CtypesPermission
            elif name.startswith("cpython."):
                cls = CpythonPermission
        return super().__new__(cls)

    def __init__(self, name, allowed, *, log=True, target=None):
        self.name = name
        self.allowed = allowed
        self.log = log
        self.target = target

    def type(self):
        if type(self) == Permission:
            return "generic"
        else:
            mro = type(self).mro()
            name = ""
            for item in mro:
                if item == Permission:
                    break
                name = item.__name__.lower().replace("permission", "") + "." + name
            return name.rstrip(".")


class SecurityPermission(Permission):
    pass


class ProcessPermission(Permission):
    pass


class IOPermission(Permission):
    pass


class SocketPermission(IOPermission):
    pass


class FilePermission(IOPermission):
    pass


class NetworkPermission(IOPermission):
    pass


class FtpPermission(NetworkPermission):
    pass


class TelnetPermission(NetworkPermission):
    pass


class ImapPermission(NetworkPermission):
    pass


class PopPermission(NetworkPermission):
    pass


class NntpPermission(NetworkPermission):
    pass


class SmtpPermission(NetworkPermission):
    pass


class SqlPermission(IOPermission):
    pass


class Sqlite3Permission(SqlPermission):
    pass


class MetaPermission(Permission):
    pass


class ReflectionPermission(MetaPermission):
    pass


class CodePermission(MetaPermission):
    pass


class DebugPermission(Permission):
    pass


class NativePermission(Permission):
    pass


class CtypesPermission(NativePermission):
    pass


class CpythonPermission(NativePermission):
    pass
