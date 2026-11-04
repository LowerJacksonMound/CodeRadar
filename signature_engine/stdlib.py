"""
Python standard library module registry.

Contains the complete list of Python 3.13+ standard library modules
and legacy modules that have been removed ("Dead Batteries" PEP 594).
"""

import logging
import os

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)


# Python 3.13+ Standard Library Modules
# This is the authoritative list of stdlib modules
STDLIB_MODULES: frozenset[str] = frozenset({
    # Text Processing
    "string",
    "re",
    "difflib",
    "textwrap",
    "unicodedata",
    "stringprep",
    "readline",
    "rlcompleter",

    # Binary Data
    "struct",
    "codecs",

    # Data Types
    "datetime",
    "zoneinfo",
    "calendar",
    "collections",
    "heapq",
    "bisect",
    "array",
    "weakref",
    "types",
    "copy",
    "pprint",
    "reprlib",
    "enum",
    "graphlib",

    # Numeric and Mathematical
    "numbers",
    "math",
    "cmath",
    "decimal",
    "fractions",
    "random",
    "statistics",

    # Functional Programming
    "itertools",
    "functools",
    "operator",

    # File and Directory Access
    "pathlib",
    "os.path",
    "fileinput",
    "stat",
    "filecmp",
    "tempfile",
    "glob",
    "fnmatch",
    "linecache",
    "shutil",

    # Data Persistence
    "pickle",
    "copyreg",
    "shelve",
    "marshal",
    "dbm",
    "sqlite3",

    # Data Compression
    "zlib",
    "gzip",
    "bz2",
    "lzma",
    "zipfile",
    "tarfile",

    # File Formats
    "csv",
    "configparser",
    "tomllib",
    "netrc",
    "plistlib",

    # Cryptographic
    "hashlib",
    "hmac",
    "secrets",

    # OS Services
    "os",
    "io",
    "time",
    "argparse",
    "getopt",
    "logging",
    "getpass",
    "curses",
    "platform",
    "errno",
    "ctypes",

    # Concurrent Execution
    "threading",
    "multiprocessing",
    "concurrent",
    "subprocess",
    "sched",
    "queue",
    "contextvars",
    "_thread",

    # Networking
    "asyncio",
    "socket",
    "ssl",
    "select",
    "selectors",
    "signal",
    "mmap",

    # Internet Data Handling
    "email",
    "json",
    "mailbox",
    "mimetypes",
    "base64",
    "binascii",
    "quopri",

    # HTML/XML Processing
    "html",
    "xml",

    # Internet Protocols
    "webbrowser",
    "wsgiref",
    "urllib",
    "http",
    "ftplib",
    "poplib",
    "imaplib",
    "smtplib",
    "uuid",
    "socketserver",
    "xmlrpc",
    "ipaddress",

    # Multimedia
    "wave",
    "colorsys",

    # Internationalization
    "gettext",
    "locale",

    # Program Frameworks
    "turtle",
    "cmd",
    "shlex",

    # GUI
    "tkinter",
    "idlelib",

    # Development Tools
    "typing",
    "pydoc",
    "doctest",
    "unittest",
    "test",

    # Debugging and Profiling
    "bdb",
    "faulthandler",
    "pdb",
    "timeit",
    "trace",
    "tracemalloc",

    # Software Packaging
    "ensurepip",
    "venv",
    "zipapp",

    # Python Runtime
    "sys",
    "sysconfig",
    "builtins",
    "warnings",
    "dataclasses",
    "contextlib",
    "abc",
    "atexit",
    "traceback",
    "__future__",
    "gc",
    "inspect",
    "site",

    # Custom Importers
    "zipimport",
    "pkgutil",
    "modulefinder",
    "runpy",
    "importlib",

    # Language Services
    "ast",
    "symtable",
    "token",
    "keyword",
    "tokenize",
    "tabnanny",
    "pyclbr",
    "py_compile",
    "compileall",
    "dis",
    "pickletools",

    # Unix Specific
    "posix",
    "pwd",
    "grp",
    "termios",
    "tty",
    "pty",
    "fcntl",
    "resource",
    "syslog",

    # Windows Specific
    "msvcrt",
    "winreg",
    "winsound",

    # Superseded (but still available)
    "optparse",

    # Additional modules
    "cProfile",
    "profile",
    "code",
    "codeop",
})

# Legacy/Removed Modules (PEP 594 - "Dead Batteries")
# These were removed in Python 3.13
LEGACY_STDLIB_MODULES: frozenset[str] = frozenset({
    # Removed in Python 3.13 (PEP 594)
    "aifc",          # AIFF audio format
    "audioop",       # Audio operations
    "cgi",           # CGI support
    "cgitb",         # CGI traceback manager
    "chunk",         # IFF chunk reading
    "crypt",         # Unix crypt function
    "imghdr",        # Image type detection
    "mailcap",       # Mailcap file handling
    "msilib",        # Windows MSI files
    "nis",           # NIS/YP support
    "nntplib",       # NNTP protocol
    "ossaudiodev",   # OSS audio interface
    "pipes",         # Shell pipeline templates
    "sndhdr",        # Sound type detection
    "spwd",          # Shadow password database
    "sunau",         # Sun AU audio format
    "telnetlib",     # Telnet client
    "uu",            # UUencode/decode
    "xdrlib",        # XDR data encoding

    # Deprecated and scheduled for removal
    "asyncore",      # Async socket handler (use asyncio)
    "asynchat",      # Async socket command/response handler
    "smtpd",         # SMTP server (removed in 3.12)

    # Other legacy modules often confused with stdlib
    "imp",           # Deprecated import utilities (use importlib)
    "formatter",     # Abstract formatter (removed in 3.10)
    "parser",        # Python parser (removed in 3.10)
    "symbol",        # Python grammar symbols (removed in 3.10)
    "lib2to3",       # 2to3 library
    "distutils",     # Deprecated packaging (removed in 3.12)
})

# All known valid Python modules (stdlib + legacy for detection)
ALL_KNOWN_MODULES: frozenset[str] = STDLIB_MODULES | LEGACY_STDLIB_MODULES


def is_stdlib_module(name: str) -> bool:
    """Check if a module name is in the current stdlib."""
    result = name in STDLIB_MODULES
    _trace("is_stdlib_module(%s) -> %s", name, result)
    return result


def is_legacy_module(name: str) -> bool:
    """Check if a module name is a legacy/removed module."""
    result = name in LEGACY_STDLIB_MODULES
    _trace("is_legacy_module(%s) -> %s", name, result)
    return result


def is_known_module(name: str) -> bool:
    """Check if a module name is known (stdlib or legacy)."""
    result = name in ALL_KNOWN_MODULES
    _trace("is_known_module(%s) -> %s", name, result)
    return result


def get_module_status(name: str) -> str:
    """Get the status of a module name.

    Returns:
        'stdlib' - Current standard library
        'legacy' - Removed/deprecated
        'unknown' - Not a known module
    """
    if name in STDLIB_MODULES:
        _trace("get_module_status(%s) -> stdlib", name)
        return "stdlib"
    if name in LEGACY_STDLIB_MODULES:
        _trace("get_module_status(%s) -> legacy", name)
        return "legacy"
    _trace("get_module_status(%s) -> unknown", name)
    return "unknown"


if __name__ == "__main__":
    import sys

    print("signature_engine.stdlib — Standard library registry")
    print(f"  Stdlib modules: {len(STDLIB_MODULES)}")
    print(f"  Legacy modules: {len(LEGACY_STDLIB_MODULES)}")
    print(f"  All known: {len(ALL_KNOWN_MODULES)}")

    if len(sys.argv) > 1:
        name = sys.argv[1]
        print(f"\nLookup: '{name}'")
        print(f"  status: {get_module_status(name)}")
