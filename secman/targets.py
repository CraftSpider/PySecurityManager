
import abc


class Target(abc.ABC):

    def __init_subclass__(cls, **kwargs):
        if cls.mro()[1] != Target:
            raise TypeError(f"{cls.mro()[1].__name__} class is final")

    @abc.abstractmethod
    def check(self, audit, args, frame):
        raise NotImplementedError()


class FileTarget(Target):

    def __init__(self, *, path=..., file=...):
        if file is ... and path is ...:
            raise AttributeError("Either file or path must be specified")
        if file is not ... and path is not ...:
            raise AttributeError("Only one of file and path can be specified")

        self.path = path
        self.file = file


class FrameTarget(Target):

    def __init__(self, *, locals=..., globals=..., lineno=..., trace_lines=..., trace_opcodes=...):
        self.locals = locals
        self.globals = globals
        self.lineno = lineno
        self.trace_lines = trace_lines
        self.trace_opcodes = trace_opcodes


class CodeTarget(Target):

    def __init__(self, *, name=..., argcount=..., posonly_argcount=..., kwonly_argcount=..., nlocals=..., varnames=...,
                 cellvars=..., freevars=..., consts=..., names=..., filename=..., firstlineno=..., lnotab=...,
                 stacksize=..., flags=...):
        self.name = name
        self.argcount = argcount
        self.posonly_argcount = posonly_argcount
        self.kwonly_argcount = kwonly_argcount
        self.nlocals = nlocals
        self.varnames = varnames
        self.cellvars = cellvars
        self.freevars = freevars
        self.consts = consts
        self.names = names
        self.filename = filename
        self.firstlineno = firstlineno
        self.lnotab = lnotab
        self.stacksize = stacksize
        self.flags = flags
