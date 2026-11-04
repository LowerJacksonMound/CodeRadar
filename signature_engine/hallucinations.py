"""
Hallucination detection patterns for AI-generated Python code.

Contains common misspellings, fake modules, and patterns that
indicate hallucinated or fabricated code.
"""

import logging
import os

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)


# Common Misspelled Builtins (typo -> correct)
# These are typos that AI models commonly generate
MISSPELLED_BUILTINS: dict[str, str] = {
    # Length/Size typos
    "lenght": "len",
    "lenth": "len",
    "legth": "len",
    "legnth": "len",
    "lengh": "len",

    # Print typos
    "pritn": "print",
    "pirnt": "print",
    "prit": "print",
    "prnt": "print",
    "prin": "print",
    "printf": "print",  # C-style confusion

    # Return typos
    "retrun": "return",
    "reutrn": "return",
    "retrn": "return",
    "retunr": "return",
    "rerturn": "return",

    # Range typos
    "rnage": "range",
    "ragne": "range",
    "raneg": "range",
    "ragn": "range",

    # String typos
    "stirng": "str",
    "strng": "str",
    "sting": "str",
    "strig": "str",
    "srting": "str",

    # Integer typos
    "integr": "int",
    "interger": "int",
    "intger": "int",
    "iteger": "int",

    # Float typos
    "flot": "float",
    "flaot": "float",
    "floar": "float",

    # List typos
    "lsit": "list",
    "lis": "list",
    "lits": "list",
    "lisr": "list",

    # Dict typos
    "dct": "dict",
    "dicr": "dict",
    "dicit": "dict",
    "dicitonary": "dict",
    "dictioanry": "dict",

    # Tuple typos
    "tupe": "tuple",
    "tupl": "tuple",
    "tupel": "tuple",
    "tulpe": "tuple",

    # Boolean typos
    "boolean": "bool",
    "boolen": "bool",
    "bolean": "bool",
    "bol": "bool",

    # True/False typos
    "Ture": "True",
    "ture": "True",
    "TURE": "True",
    "Fasle": "False",
    "fasle": "False",
    "flase": "False",
    "FLASE": "False",
    "Flase": "False",

    # None typos
    "NONe": "None",
    "none": "None",  # lowercase
    "NONE": "None",
    "Noen": "None",
    "NOne": "None",

    # Import typos
    "improt": "import",
    "imoprt": "import",
    "ipmort": "import",
    "imprort": "import",
    "impor": "import",

    # From typos
    "fom": "from",
    "frm": "from",

    # Class typos
    "calss": "class",
    "clss": "class",
    "clas": "class",
    "classs": "class",

    # Function typos
    "fucntion": "function",
    "funciton": "function",
    "funtion": "function",
    "functon": "function",
    "funcion": "function",

    # Def typos
    "dfe": "def",
    "dfef": "def",

    # Lambda typos
    "lamda": "lambda",
    "lamba": "lambda",
    "labmda": "lambda",
    "lamdba": "lambda",

    # Enumerate typos
    "enumrate": "enumerate",
    "enumearte": "enumerate",
    "enuemrate": "enumerate",
    "enumerae": "enumerate",

    # Isinstance typos
    "instnace": "isinstance",
    "isinstnace": "isinstance",
    "isnstance": "isinstance",
    "isintance": "isinstance",

    # Exception typos
    "exeption": "exception",
    "excepton": "exception",
    "excpetion": "exception",
    "exceptoin": "exception",

    # Raise typos
    "riase": "raise",
    "rasie": "raise",
    "rais": "raise",

    # Assert typos
    "assrt": "assert",
    "asert": "assert",
    "assret": "assert",

    # Break typos
    "brak": "break",
    "braek": "break",

    # Continue typos
    "contniue": "continue",
    "contineu": "continue",
    "contnue": "continue",

    # Global typos
    "gloabl": "global",
    "gloal": "global",
    "globa": "global",

    # Async/await typos
    "aysnc": "async",
    "aync": "async",
    "asycn": "async",
    "awiat": "await",
    "awit": "await",

    # Yield typos
    "yeild": "yield",
    "yiled": "yield",
    "yeld": "yield",

    # With typos
    "wtih": "with",
    "wiht": "with",

    # Pass typos
    "pss": "pass",

    # Try/Except typos
    "excpet": "except",
    "exept": "except",
    "excep": "except",
    "excetp": "except",

    # Finally typos
    "finaly": "finally",
    "finnaly": "finally",
    "finially": "finally",

    # Self typos
    "slef": "self",
    "sefl": "self",
    "selef": "self",

    # Init typos
    "inti": "__init__",
    "initt": "__init__",

    # Open typos
    "opne": "open",
    "oen": "open",

    # Append typos
    "appned": "append",
    "apend": "append",
    "apppend": "append",
    "apppned": "append",

    # Sorted typos
    "sorte": "sorted",
    "sortd": "sorted",
    "soretd": "sorted",

    # Reversed typos
    "reveresed": "reversed",
    "revresed": "reversed",
    "reversde": "reversed",

    # Items/keys/values typos
    "itmes": "items",
    "iteams": "items",
    "kyes": "keys",
    "keyes": "keys",
    "vlaues": "values",
    "valeus": "values",

    # Join typos
    "jion": "join",
    "joing": "join",

    # Split typos
    "spilt": "split",
    "splti": "split",

    # Strip typos
    "stirp": "strip",
    "strp": "strip",

    # Format typos
    "fromat": "format",
    "foramt": "format",
    "fomat": "format",

    # Replace typos
    "repalce": "replace",
    "replcae": "replace",
    "repace": "replace",

    # Index typos
    "idnex": "index",
    "indx": "index",
    "inedx": "index",

    # Count typos
    "ocunt": "count",
    "coutn": "count",
    "cout": "count",

    # Remove typos
    "remvoe": "remove",
    "reomve": "remove",
    "rmove": "remove",

    # Update typos
    "udpate": "update",
    "updat": "update",
    "upadte": "update",

    # Pop typos
    "popp": "pop",

    # Get typos
    "gett": "get",

    # Set typos
    "sett": "set",

    # Has typos
    "hsa": "has",

    # All typos
    "alll": "all",

    # Any typos
    "anyy": "any",

    # Map typos
    "mpa": "map",
    "maap": "map",

    # Filter typos
    "fliter": "filter",
    "fitler": "filter",
    "fiter": "filter",

    # Zip typos
    "zpi": "zip",
    "ziip": "zip",

    # Sum typos
    "summ": "sum",
    "usm": "sum",

    # Min/max typos
    "mni": "min",
    "miin": "min",
    "mxa": "max",
    "maxx": "max",

    # Abs typos
    "asb": "abs",
    "abbs": "abs",

    # Round typos
    "roudn": "round",
    "roud": "round",

    # Type typos
    "tyep": "type",
    "tpye": "type",
    "ttype": "type",

    # Input typos
    "inptu": "input",
    "ipnut": "input",
    "imput": "input",

    # File typos
    "fiel": "file",
    "flie": "file",

    # Read typos
    "raed": "read",
    "reda": "read",

    # Write typos
    "wirte": "write",
    "wrtie": "write",
    "wriet": "write",

    # Close typos
    "clsoe": "close",
    "colse": "close",

    # Exit typos
    "exti": "exit",
    "eixt": "exit",
}

# Hallucinated Module Patterns
# These are fake modules that AI models commonly generate
HALLUCINATION_MODULE_PATTERNS: frozenset[str] = frozenset({
    # Generic utility modules (don't exist in stdlib)
    "utils",
    "utility",
    "utilities",
    "util",
    "helpers",
    "helper",
    "common",
    "commons",
    "shared",
    "tools",
    "toolkit",
    "toolbox",
    "lib",
    "libs",
    "misc",
    "general",

    # Data-related fake modules
    "data_utils",
    "datautils",
    "data_helpers",
    "data_processing",
    "data_loader",
    "dataloader",
    "data_handler",
    "data_manager",
    "database_utils",
    "db_utils",
    "dbutils",

    # File-related fake modules
    "file_utils",
    "fileutils",
    "file_helpers",
    "file_handler",
    "file_manager",
    "io_utils",
    "ioutils",
    "path_utils",
    "pathutils",

    # String-related fake modules
    "string_utils",
    "stringutils",
    "str_utils",
    "strutils",
    "text_utils",
    "textutils",

    # Config-related fake modules
    "config_utils",
    "configutils",
    "settings_utils",
    "env_utils",

    # Network-related fake modules
    "network_utils",
    "networkutils",
    "net_utils",
    "netutils",
    "http_utils",
    "httputils",
    "api_utils",
    "apiutils",
    "request_utils",

    # Time-related fake modules
    "time_utils",
    "timeutils",
    "date_utils",
    "dateutils",
    "datetime_utils",

    # Math-related fake modules
    "math_utils",
    "mathutils",
    "numeric_utils",
    "numutils",
    "calc_utils",

    # Validation-related fake modules
    "validation_utils",
    "validationutils",
    "validator_utils",
    "input_validation",
    "form_utils",

    # Error/Exception fake modules
    "error_utils",
    "errorutils",
    "exception_utils",
    "error_handler",
    "error_handling",

    # Log-related fake modules
    "log_utils",
    "logutils",
    "logger_utils",
    "logging_utils",

    # Test-related fake modules
    "test_utils",
    "testutils",
    "testing_utils",
    "test_helpers",

    # Security-related fake modules
    "security_utils",
    "securityutils",
    "auth_utils",
    "authutils",
    "crypto_utils",

    # Image/Media fake modules
    "image_utils",
    "imageutils",
    "img_utils",
    "media_utils",
    "video_utils",

    # Format-related fake modules
    "json_utils",
    "jsonutils",
    "xml_utils",
    "xmlutils",
    "csv_utils",
    "yaml_utils",

    # Cache-related fake modules
    "cache_utils",
    "cacheutils",
    "memory_utils",

    # Email-related fake modules
    "email_utils",
    "emailutils",
    "mail_utils",

    # User-related fake modules
    "user_utils",
    "userutils",
    "account_utils",
    "profile_utils",

    # Generic service modules
    "service_utils",

    # Web-related fake modules
    "web_utils",
    "webutils",
    "url_utils",
    "urlutils",
    "html_utils",

    # Build/Deploy fake modules
    "build_utils",
    "deploy_utils",
    "ci_utils",

    # ML/AI fake modules
    "ml_utils",
    "mlutils",
    "ai_utils",
    "model_utils",
    "train_utils",
    "dataset_utils",

    # Cloud fake modules
    "aws_utils",
    "cloud_utils",
    "azure_utils",
    "gcp_utils",

    # CLI fake modules
    "cli_utils",
    "cliutils",
    "command_utils",
    "arg_utils",

    # System fake modules
    "system_utils",
    "sysutils",
    "os_utils",
    "platform_utils",

    # Process fake modules
    "process_utils",
    "thread_utils",
    "async_utils",

    # Collection fake modules
    "list_utils",
    "dict_utils",
    "array_utils",
    "collection_utils",

    # Parse fake modules
    "parse_utils",
    "parser_utils",
    "parsing_utils",

    # Convert/Transform fake modules
    "convert_utils",
    "transform_utils",
    "format_utils",
    "encoding_utils",
})

# Misspelled module names
MISSPELLED_MODULES: dict[str, str] = {
    # stdlib misspellings
    "asynco": "asyncio",
    "asycnio": "asyncio",
    "asycio": "asyncio",
    "pathilb": "pathlib",
    "pahtlib": "pathlib",
    "dataclases": "dataclasses",
    "datacalsses": "dataclasses",
    "funcitools": "functools",
    "funcotols": "functools",
    "itertols": "itertools",
    "iterotols": "itertools",
    "collctions": "collections",
    "colections": "collections",
    "tyipng": "typing",
    "typign": "typing",
    "loging": "logging",
    "loggin": "logging",
    "loggign": "logging",
    "jsno": "json",
    "josn": "json",
    "arguparse": "argparse",
    "agrparse": "argparse",
    "subproccess": "subprocess",
    "subproces": "subprocess",
    "systme": "sys",
    "ssytem": "sys",
    "urnlib": "urllib",
    "urlib": "urllib",
    "htttp": "http",
    "regxe": "re",
    "reegx": "re",
    "randmo": "random",
    "ranodm": "random",
    "datetiem": "datetime",
    "datetim": "datetime",
    "datetme": "datetime",
    "treading": "threading",
    "thredaing": "threading",
    "mulitprocessing": "multiprocessing",
    "multiporcessing": "multiprocessing",
    "contxetlib": "contextlib",
    "contetxlib": "contextlib",
    "unitest": "unittest",
    "uintest": "unittest",
    "tempfiel": "tempfile",
    "tmepfile": "tempfile",
    "shutl": "shutil",
    "shtil": "shutil",
    "hashlb": "hashlib",
    "hashilb": "hashlib",
    "staitstics": "statistics",
    "statsitics": "statistics",
    "deicmal": "decimal",
    "decimla": "decimal",
    "fractinos": "fractions",
    "fractoins": "fractions",
    "configpaser": "configparser",
    "confgiparser": "configparser",
    "pikcle": "pickle",
    "pickel": "pickle",
    "sockect": "socket",
    "sokcet": "socket",
    "slect": "select",
    "selcet": "select",
    "singal": "signal",
    "signla": "signal",
    "platfomr": "platform",
    "platfrom": "platform",
    "erron": "errno",
    "errono": "errno",
    "ctpyes": "ctypes",
    "ctyeps": "ctypes",
    "strig": "string",
    "stirng": "string",
    "textwap": "textwrap",
    "textwarpp": "textwrap",
    "difflbi": "difflib",
    "diffflib": "difflib",
    "sturt": "struct",
    "strcut": "struct",
    "codecc": "codecs",
    "codces": "codecs",
    "claendar": "calendar",
    "calander": "calendar",
    "heaqp": "heapq",
    "heapqq": "heapq",
    "bisetc": "bisect",
    "bsiect": "bisect",
    "arrary": "array",
    "arrya": "array",
    "weakrf": "weakref",
    "weakrfe": "weakref",
    "tyeps": "types",
    "tpyes": "types",
    "ppirnt": "pprint",
    "priprint": "pprint",
    "repilib": "reprlib",
    "replirb": "reprlib",
    "enuem": "enum",
    "enmu": "enum",
    "numebers": "numbers",
    "nubmers": "numbers",
    "cmtah": "cmath",
    "cmmath": "cmath",
    "oeprator": "operator",
    "operaotr": "operator",
    "fileiupt": "fileinput",
    "fileipnut": "fileinput",
    "filecomp": "filecmp",
    "filecpm": "filecmp",
    "glbo": "glob",
    "globb": "glob",
    "fnmacth": "fnmatch",
    "fnamtch": "fnmatch",
    "linecahce": "linecache",
    "linceache": "linecache",
    "tarfiel": "tarfile",
    "tarflie": "tarfile",
    "zipfiel": "zipfile",
    "zipflie": "zipfile",
    "gzpi": "gzip",
    "gizp": "gzip",
    "secrest": "secrets",
    "secerts": "secrets",
    "getpas": "getpass",
    "getpss": "getpass",
    "cursese": "curses",
    "curesss": "curses",
    "scehd": "sched",
    "schde": "sched",
    "qeuue": "queue",
    "quuee": "queue",
    "contextvras": "contextvars",
    "contexvars": "contextvars",
    "selectros": "selectors",
    "seletcors": "selectors",
    "mimetpyes": "mimetypes",
    "baes64": "base64",
    "base46": "base64",
    "binasciii": "binascii",
    "bianscii": "binascii",
    "webbrowsr": "webbrowser",
    "webbroswer": "webbrowser",
    "socketsrver": "socketserver",
    "socketserevr": "socketserver",
    "ipaddres": "ipaddress",
    "ipaddresss": "ipaddress",
    "gettetx": "gettext",
    "gettexxt": "gettext",
    "lcoale": "locale",
    "locael": "locale",
    "shlxe": "shlex",
    "shellx": "shlex",
    "tkniter": "tkinter",
    "tkitner": "tkinter",
    "pydco": "pydoc",
    "pyodc": "pydoc",
    "dctest": "doctest",
    "doctset": "doctest",
    "faulthandlre": "faulthandler",
    "faulthanlder": "faulthandler",
    "tmieit": "timeit",
    "timiet": "timeit",
    "tracmealloc": "tracemalloc",
    "traceamllloc": "tracemalloc",
    "ensureppi": "ensurepip",
    "esurepip": "ensurepip",
    "zipaap": "zipapp",
    "zipappp": "zipapp",
    "sysconfgi": "sysconfig",
    "sysfconfig": "sysconfig",
    "buliitns": "builtins",
    "builtnis": "builtins",
    "warnigns": "warnings",
    "wanrings": "warnings",
    "tracebcak": "traceback",
    "tarceabck": "traceback",
    "zipimoprt": "zipimport",
    "zipimoort": "zipimport",
    "pkguilt": "pkgutil",
    "pkgtuil": "pkgutil",
    "modulefdiner": "modulefinder",
    "modulefidner": "modulefinder",
    "rynpu": "runpy",
    "rnupy": "runpy",
    "improtlib": "importlib",
    "importilb": "importlib",
    "symtalbe": "symtable",
    "symtabel": "symtable",
    "toekn": "token",
    "tokne": "token",
    "keywrod": "keyword",
    "keywor": "keyword",
    "tokneize": "tokenize",
    "toknize": "tokenize",
    "tabnanyn": "tabnanny",
    "tabnnany": "tabnanny",
    "pycblr": "pyclbr",
    "pyclrb": "pyclbr",
    "py_complei": "py_compile",
    "py_comiple": "py_compile",
    "compileallll": "compileall",
    "compilleall": "compileall",
    "pickeltoos": "pickletools",
    "pickletolos": "pickletools",
}

# Common fake function/method names
HALLUCINATED_FUNCTIONS: frozenset[str] = frozenset({
    # Fake list methods
    "append_all",
    "prepend",
    "insert_all",
    "remove_all",
    "delete",
    "add",  # On list, should be append

    # Fake string methods
    "contains",  # Should be "in" operator
    "to_lower",
    "to_upper",
    "to_string",
    "to_str",
    "from_string",
    "from_str",
    "trim",  # Should be strip
    "substring",  # Should use slicing
    "length",  # Should be len()
    "size",  # Should be len()
    "char_at",
    "index_of",  # Should be index or find
    "last_index_of",
    "equals",  # Should use ==
    "equals_ignore_case",
    "compare_to",

    # Fake dict methods
    "has_key",  # Deprecated, use "in"
    "contains_key",
    "contains_value",
    # "put" REMOVED IG-10 (2026-09-06): queue.Queue.put / asyncio.Queue.put / dict-like APIs — a stdlib method, not Java
    "remove_key",
    "get_or_default",

    # Fake file methods
    "read_all",
    "read_line",  # Should be readline
    "read_lines",  # Should be readlines
    "write_all",
    "write_line",  # Should be write + \n
    "write_lines",  # Should be writelines
    "append_line",

    # Fake type conversion
    "to_int",
    "to_float",
    "to_bool",
    "to_list",
    "to_dict",
    "to_set",
    "to_tuple",
    "parse_int",
    "parse_float",
    "as_string",
    "as_int",

    # Fake collection methods
    "is_empty",  # Should be "not collection"
    "is_not_empty",
    "first",  # Should be [0]
    "last",  # Should be [-1]
    "head",
    "tail",
    "take",
    "drop",
    "flatten",  # Need itertools.chain
    "distinct",  # Should use set()
    "unique",

    # Fake iteration methods
    "for_each",  # Should use for loop
    "map_each",
    "filter_by",
    "find_first",
    "find_all",
    "find_one",

    # Fake existence checks
    "not_exists",
    "is_null",
    "is_not_null",
    "is_none",  # Should use "is None"
    "is_not_none",

    # Fake async methods
    # "wait" REMOVED IG-10 (2026-09-06): Popen.wait / Event.wait / Condition.wait / Future — a stdlib method, not a typo
    "async_run",
    "run_async",
    "execute_async",

    # Fake error methods
    "throw",  # Should be raise
    "catch",  # Should use except
    "try_catch",

    # Fake object methods
    "clone",  # Should use copy
    "deep_clone",
    "to_json",  # Need json.dumps
    "from_json",  # Need json.loads
    "to_yaml",
    "from_yaml",
    "serialize",
    "deserialize",
})


def is_misspelled_builtin(name: str) -> bool:
    """Check if a name is a misspelled builtin."""
    result = name in MISSPELLED_BUILTINS
    _trace("is_misspelled_builtin(%s) -> %s", name, result)
    return result


def get_correct_builtin(typo: str) -> str | None:
    """Get the correct builtin for a typo."""
    result = MISSPELLED_BUILTINS.get(typo)
    _trace("get_correct_builtin(%s) -> %s", typo, result)
    return result


def is_hallucinated_module(name: str) -> bool:
    """Check if a module name is likely hallucinated."""
    result = name in HALLUCINATION_MODULE_PATTERNS
    _trace("is_hallucinated_module(%s) -> %s", name, result)
    return result


def is_misspelled_module(name: str) -> bool:
    """Check if a module name is misspelled."""
    result = name in MISSPELLED_MODULES
    _trace("is_misspelled_module(%s) -> %s", name, result)
    return result


def get_correct_module(typo: str) -> str | None:
    """Get the correct module name for a typo."""
    result = MISSPELLED_MODULES.get(typo)
    _trace("get_correct_module(%s) -> %s", typo, result)
    return result


def is_hallucinated_function(name: str) -> bool:
    """Check if a function name is likely hallucinated."""
    result = name in HALLUCINATED_FUNCTIONS
    _trace("is_hallucinated_function(%s) -> %s", name, result)
    return result


def get_all_typos() -> dict[str, str]:
    """Get all typo -> correction mappings."""
    result = dict(MISSPELLED_BUILTINS)
    result.update(MISSPELLED_MODULES)
    _trace("get_all_typos: %d mappings", len(result))
    return result


def find_similar_builtin(name: str, threshold: float = 0.0) -> str | None:  # EXCISED cut 3 batch 3 (2026-09-06, deferred sites cut on reading): was 0.8 — the best match is returned with its ratio traced; the consumer publishes both
    """Find a similar builtin if the name might be a typo.

    Uses simple Levenshtein distance ratio.
    """
    _trace("find_similar_builtin(%s, threshold=%.2f)", name, threshold)
    from difflib import SequenceMatcher

    # Check direct typo mapping first
    if name in MISSPELLED_BUILTINS:
        return MISSPELLED_BUILTINS[name]

    # Import builtin list
    from signature_engine.builtins_registry import PYTHON_BUILTINS

    best_match = None
    best_ratio = 0.0

    for builtin in PYTHON_BUILTINS:
        ratio = SequenceMatcher(None, name.lower(), builtin.lower()).ratio()
        if ratio > best_ratio and ratio >= threshold:
            best_ratio = ratio
            best_match = builtin

    _trace("find_similar_builtin(%s) -> %s (ratio=%.3f)", name, best_match, best_ratio)
    return best_match


if __name__ == "__main__":
    import sys

    print("signature_engine.hallucinations — Typo/hallucination registry")
    print(f"  Misspelled builtins: {len(MISSPELLED_BUILTINS)}")
    print(f"  Hallucination module patterns: {len(HALLUCINATION_MODULE_PATTERNS)}")
    print(f"  Misspelled modules: {len(MISSPELLED_MODULES)}")
    print(f"  Hallucinated functions: {len(HALLUCINATED_FUNCTIONS)}")

    # Interactive lookup if argument given
    if len(sys.argv) > 1:
        name = sys.argv[1]
        print(f"\nLookup: '{name}'")
        print(f"  is_misspelled_builtin: {is_misspelled_builtin(name)}")
        correct = get_correct_builtin(name)
        if correct:
            print(f"  correct_builtin: {correct}")
        print(f"  is_hallucinated_module: {is_hallucinated_module(name)}")
        print(f"  is_misspelled_module: {is_misspelled_module(name)}")
        similar = find_similar_builtin(name)
        if similar:
            print(f"  similar_builtin: {similar} (best match; the ratio is in the trace — no cut at 0.8)")
