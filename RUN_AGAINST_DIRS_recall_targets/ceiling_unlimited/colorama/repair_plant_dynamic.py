"""Planted counterfeits for NAI-219 / NAI-225 / SEC-001 / SEC-002 / SEC-003 — set 4b-04 (2026-09-10). A constant
lambda, a call to a function nothing defines, and the three dynamic-execution calls: what the lambda should
compute, which function was meant, and what each dynamic call should become are the author's intent —
no-fix-by-design rows, nothing to rewrite."""
import pickle

always_zero = lambda x: 0


def total(values):
    return summarise(values)


def evaluate(expr):
    return eval(expr)


def run(code):
    exec(code)


def restore(blob):
    return pickle.loads(blob)
