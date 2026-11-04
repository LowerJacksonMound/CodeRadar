"""Planted counterfeits for NAI-203 / NAI-204 / NAI-206 / NAI-210 — set 4b-12 (2026-09-10), the last set of family
safety and of portion A. A cached function with a side effect, a sync function running a coroutine, a path built on
os.getcwd(), and a thread spawned inside a sync function."""
import asyncio
import logging
import os
import threading
from functools import lru_cache


@lru_cache(maxsize=32)
def describe(code):
    logging.info("describing %s", code)
    return "code-" + str(code)


def run_sync(coro):
    return asyncio.run(coro)


def data_path(name):
    base = os.path.join(os.getcwd(), "data")
    return base + name


def spawn(target):
    worker = threading.Thread(target=target)
    worker.start()
    return worker
