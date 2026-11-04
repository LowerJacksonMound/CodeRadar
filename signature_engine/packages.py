"""
Common third-party Python packages registry.

Contains categorized lists of well-known third-party packages
to help distinguish real packages from hallucinated ones.
"""

import logging
import os

logger = logging.getLogger(__name__)
DEBUG = os.environ.get("SIGNATURE_ENGINE_DEBUG", "").lower() in ("1", "true", "yes")


def _trace(msg: str, *args: object) -> None:
    if DEBUG:
        logger.debug(msg, *args)


# Data Science & ML Packages
DATA_SCIENCE_PACKAGES: frozenset[str] = frozenset({
    # Core data science
    "numpy",
    "pandas",
    "scipy",
    "scikit-learn",
    "sklearn",
    "statsmodels",

    # Visualization
    "matplotlib",
    "seaborn",
    "plotly",
    "bokeh",
    "altair",

    # Deep Learning
    "torch",
    "pytorch",
    "tensorflow",
    "keras",
    "jax",
    "flax",
    "transformers",
    "huggingface_hub",

    # ML Tools
    "xgboost",
    "lightgbm",
    "catboost",
    "optuna",
    "mlflow",
    "wandb",
    "dvc",

    # NLP
    "nltk",
    "spacy",
    "gensim",
    "textblob",
    "flair",
    "sentence_transformers",

    # Computer Vision
    "opencv-python",
    "cv2",
    "pillow",
    "PIL",
    "imageio",
    "albumentations",
    "torchvision",

    # Data Processing
    "polars",
    "dask",
    "vaex",
    "modin",
    "pyarrow",
    "feather",
})

# Web Frameworks & HTTP
WEB_PACKAGES: frozenset[str] = frozenset({
    # Web Frameworks
    "flask",
    "django",
    "fastapi",
    "starlette",
    "tornado",
    "bottle",
    "pyramid",
    "falcon",
    "sanic",
    "aiohttp",
    "quart",
    "litestar",

    # HTTP Clients
    "requests",
    "httpx",
    "urllib3",
    "httplib2",

    # API Tools
    "pydantic",
    "marshmallow",
    "graphene",
    "strawberry",
    "ariadne",

    # ASGI/WSGI
    "uvicorn",
    "gunicorn",
    "hypercorn",
    "daphne",
    "waitress",

    # Web Scraping
    "beautifulsoup4",
    "bs4",
    "scrapy",
    "selenium",
    "playwright",
    "lxml",
    "parsel",

    # Templates
    "jinja2",
    "mako",
    "chameleon",
})

# Database & ORM Packages
DATABASE_PACKAGES: frozenset[str] = frozenset({
    # ORM
    "sqlalchemy",
    "sqlmodel",
    "peewee",
    "tortoise-orm",
    "pony",
    "django-orm",

    # Database Drivers
    "psycopg2",
    "psycopg",
    "pymysql",
    "mysql-connector-python",
    "pymongo",
    "motor",
    "redis",
    "aioredis",
    "cassandra-driver",
    "elasticsearch",
    "opensearch-py",

    # Migration
    "alembic",
    "yoyo-migrations",

    # Async
    "asyncpg",
    "aiomysql",
    "aiosqlite",
    "databases",
})

# CLI & DevOps Packages
DEVOPS_PACKAGES: frozenset[str] = frozenset({
    # CLI
    "click",
    "typer",
    "fire",
    "docopt",
    "rich",
    "textual",
    "prompt_toolkit",
    "tqdm",

    # Configuration
    "pyyaml",
    "yaml",
    "toml",
    "python-dotenv",
    "dynaconf",
    "hydra-core",
    "omegaconf",

    # Cloud
    "boto3",
    "botocore",
    "google-cloud-storage",
    "azure-storage-blob",
    "apache-airflow",
    "prefect",
    "dagster",
    "luigi",

    # Containers
    "docker",
    "kubernetes",
    "k8s",

    # Monitoring
    "sentry-sdk",
    "prometheus-client",
    "opentelemetry",
    "structlog",
    "loguru",
})

# Testing Packages
TESTING_PACKAGES: frozenset[str] = frozenset({
    # Test Frameworks
    "pytest",
    "nose2",
    "hypothesis",
    "behave",
    "robotframework",

    # Mocking
    "mock",
    "responses",
    "httpretty",
    "vcrpy",
    "freezegun",
    "time-machine",
    "faker",
    "factory_boy",

    # Coverage
    "coverage",
    "pytest-cov",

    # Quality
    "mypy",
    "pyright",
    "ruff",
    "black",
    "isort",
    "flake8",
    "pylint",
    "bandit",

    # Performance
    "pytest-benchmark",
    "locust",
})

# Async & Concurrency Packages
ASYNC_PACKAGES: frozenset[str] = frozenset({
    "trio",
    "anyio",
    "curio",
    "gevent",
    "eventlet",
    "greenlet",
    "celery",
    "dramatiq",
    "rq",
    "huey",
    "arq",
})

# Security & Crypto Packages
SECURITY_PACKAGES: frozenset[str] = frozenset({
    "cryptography",
    "pycryptodome",
    "pycryptodomex",
    "nacl",
    "pynacl",
    "bcrypt",
    "passlib",
    "python-jose",
    "pyjwt",
    "authlib",
    "oauthlib",
    "itsdangerous",
    "pyotp",
    "fido2",
    "webauthn",
})

# Utility Packages
UTILITY_PACKAGES: frozenset[str] = frozenset({
    # Date/Time
    "arrow",
    "pendulum",
    "python-dateutil",
    "pytz",

    # Data Validation
    "pydantic",
    "attrs",
    "cerberus",
    "voluptuous",
    "jsonschema",

    # Parsing
    "pyparsing",
    "lark",
    "ply",
    "antlr4-python3-runtime",

    # File Formats
    "openpyxl",
    "xlrd",
    "xlwt",
    "python-docx",
    "python-pptx",
    "pypdf",
    "pypdf2",
    "reportlab",
    "weasyprint",

    # Networking
    "paramiko",
    "fabric",
    "netmiko",
    "scapy",
    "pyshark",

    # Misc
    "more-itertools",
    "toolz",
    "cytoolz",
    "boltons",
    "funcy",
    "returns",
    "result",
    "shortuuid",
    "nanoid",
    "ulid",
})

# Scientific Computing Packages
SCIENTIFIC_PACKAGES: frozenset[str] = frozenset({
    "sympy",
    "networkx",
    "igraph",
    "graph-tool",
    "astropy",
    "biopython",
    "rdkit",
    "mdtraj",
    "pint",
    "uncertainties",
    "numba",
    "cython",
    "mpi4py",
    "h5py",
    "netcdf4",
    "xarray",
    "zarr",
})

# All Common Packages
COMMON_PACKAGES: frozenset[str] = (
    DATA_SCIENCE_PACKAGES |
    WEB_PACKAGES |
    DATABASE_PACKAGES |
    DEVOPS_PACKAGES |
    TESTING_PACKAGES |
    ASYNC_PACKAGES |
    SECURITY_PACKAGES |
    UTILITY_PACKAGES |
    SCIENTIFIC_PACKAGES
)

# Package category mapping
PACKAGE_CATEGORIES: dict[str, frozenset[str]] = {
    "data_science": DATA_SCIENCE_PACKAGES,
    "web": WEB_PACKAGES,
    "database": DATABASE_PACKAGES,
    "devops": DEVOPS_PACKAGES,
    "testing": TESTING_PACKAGES,
    "async": ASYNC_PACKAGES,
    "security": SECURITY_PACKAGES,
    "utility": UTILITY_PACKAGES,
    "scientific": SCIENTIFIC_PACKAGES,
}

# Import name mappings (PyPI name -> import name)
IMPORT_NAME_MAPPING: dict[str, str] = {
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
    "python-dotenv": "dotenv",
    "python-jose": "jose",
    "pyjwt": "jwt",
    "google-cloud-storage": "google.cloud.storage",
    "azure-storage-blob": "azure.storage.blob",
    "apache-airflow": "airflow",
    "more-itertools": "more_itertools",
    "graph-tool": "graph_tool",
    "python-docx": "docx",
    "python-pptx": "pptx",
    "sentry-sdk": "sentry_sdk",
    "prometheus-client": "prometheus_client",
    "huggingface_hub": "huggingface_hub",
    "sentence_transformers": "sentence_transformers",
    "hydra-core": "hydra",
    "pytorch": "torch",
}


def is_common_package(name: str) -> bool:
    """Check if a name is a known common package."""
    result = name in COMMON_PACKAGES
    _trace("is_common_package(%s) -> %s", name, result)
    return result


def get_package_category(name: str) -> str | None:
    """Get the category of a package."""
    for category, pkgs in PACKAGE_CATEGORIES.items():
        if name in pkgs:
            _trace("get_package_category(%s) -> %s", name, category)
            return category
    _trace("get_package_category(%s) -> None", name)
    return None


def get_import_name(package_name: str) -> str:
    """Get the import name for a package."""
    result = IMPORT_NAME_MAPPING.get(package_name, package_name)
    _trace("get_import_name(%s) -> %s", package_name, result)
    return result


def get_packages_by_category(category: str) -> frozenset[str]:
    """Get all packages in a category."""
    result = PACKAGE_CATEGORIES.get(category, frozenset())
    _trace("get_packages_by_category(%s) -> %d packages", category, len(result))
    return result


if __name__ == "__main__":
    import sys

    print("signature_engine.packages — Third-party package registry")
    print(f"  Common packages: {len(COMMON_PACKAGES)}")
    for cat, pkgs in sorted(PACKAGE_CATEGORIES.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"    {cat}: {len(pkgs)}")

    if len(sys.argv) > 1:
        name = sys.argv[1]
        print(f"\nLookup: '{name}'")
        print(f"  is_common: {is_common_package(name)}")
        print(f"  category: {get_package_category(name)}")
        print(f"  import_name: {get_import_name(name)}")
