"""Rules the validator itself emits (no_aivalidator/noai_validator/validator.py: HR-*, NAI-21x import facts, …) — item 4, 2026-09-08.

Set 4b-01 (2026-09-10): HR-001..HR-005 declared no-fix-by-design — each is a construct the function's
DECLARED role requires (a decorator establishes the role: @property → GETTER, @x.setter → SETTER,
@contextmanager → CONTEXT_MANAGER) and the body lacks; the missing parameters, return value, yielded
items, branch or loop are the dev's intent and cannot be written mechanically.

Set 4b-02 (2026-09-10): HR-006..HR-008 declared no-fix-by-design on the same ground (a required call,
assignment or comparison the body lacks is the dev's to write; no declared role requires one today,
so none of the three can fire — uncalled, not a defect). NAI-209 and NAI-211 (the `name = None` fallback
in an `except ImportError`) declared no-fix-by-design: whether the dependency is optional, what stands in
for it, and which side of a mismatched fallback is wrong are the dev's intent — every rewrite that
quiets the rule changes behaviour or guesses.

Set 4b-03 (2026-09-10): NAI-213, NAI-215, NAI-216, NAI-217, NAI-218 declared no-fix-by-design. An empty
bare class (213) and a hallucinated import (217) decide rows today and both name something only the dev
can write — the class's contents, the name the import meant. The import count (215), a module-level
mutable container (216) and an identity lambda (218) are warnings the Ranker passes, so none can decide
today (uncalled, not a defect); declared all the same, each a design choice no rewrite can make.

Set 4b-04 (2026-09-10): NAI-219, NAI-225, SEC-001, SEC-002, SEC-003 declared no-fix-by-design. A constant
lambda (219) and an undefined call (225) are warnings the Ranker never decides on (the call site is decided
by NAI-050, itself no-fix-by-design); the three SEC ids come from a line-regex scan the daemon's file route
never calls (eval / exec are decided there by NAI-160 / NAI-127, pickle by NAI-093). None can decide today
(uncalled, not a defect); declared all the same — what a dynamic call should become is the dev's design.

Set 4b-05 (2026-09-10): SEC-004 (Loader-less yaml.load) and SEC-005 (shell=True) are ALIAS rewriter rows —
the same function objects and roles as NAI-093 / NAI-092, which already rewrite those sites on the daemon
route; the SEC regex scan never decides a row, so a row carrying both ids would see one candidate. SEC-006
(literal password), SEC-007 (literal API key) and SEC-008 (a query built with .format) are no-fix-by-design:
where a secret should come from, and how a query and its execute call are parametrised, are the dev's
design.

Set 4b-06 (2026-09-10): SEC-010 (Popen through the shell) is a second ALIAS of NAI-092's rewriter. SEC-009
(os.system — the rewriter refuses it by design: exit status and shell semantics differ from an argv call),
SEC-011 (a literal token / secret / private key), SEC-012 (`__import__` by name — the static import it should
be needs a name the code does not carry, and `importlib.import_module` is still a dynamic import) and SEC-013
(`compile(..., 'exec')` — the same ground as exec) are no-fix-by-design. With this set every row of the
family is decided; the family closes at 4b-06.
"""
from __future__ import annotations

from . import no_fix, prescribed, rewriter, unbuilt
from .safety import fix_unsafe_deserialization, fix_unsafe_subprocess

_HR = "no_aivalidator/noai_validator/validator.py:_check_hard_requirements"
_VM = "no_aivalidator/noai_validator/validator.py:validate_module"
_VULN = "no_aivalidator/noai_validator/validator.py:check_vuln_patterns"
_SET5 = ("2026-09-10", "set 4b-05 (2026-09-10)")
_SET6 = ("2026-09-10", "set 4b-06 (2026-09-10)")

GENERATORS = [
        prescribed("HR-001", _HR,
               "Give the setter its value parameter and assign it to the backing attribute the property reads.",
               "@x.setter\ndef x(self, value):\n    self._x = value"),
        prescribed("HR-002", _HR,
               "Return the backing attribute (or the value computed from it) that the property's name promises.",
               "@property\ndef x(self):\n    return self._x"),
        prescribed("HR-003", _HR,
               "Yield the resource at the point the with-block should run, inside a try / finally that releases it.",
               "@contextmanager\ndef managed():\n    res = acquire()\n    try:\n        yield res\n    finally:\n        res.release()"),
        # 4b fact (kept, FIX_41): the role requires a branch and the body has none — the condition and both arms must be written; no declared role requires a branch today, so the rule cannot fire (uncalled, not a defect) (set 4b-01, 2026-09-10)
    prescribed("HR-004", _HR,
               "Write the branch the role requires: the condition on the input and both arms' behaviour per the intent.",
               "if <condition on input>:\n    <arm A>\nelse:\n    <arm B>"),
        # 4b fact (kept, FIX_41): the role requires a loop and the body has none — what is iterated and what each iteration does must be written; no declared role requires a loop today, so the rule cannot fire (uncalled, not a defect) (set 4b-01, 2026-09-10)
    prescribed("HR-005", _HR,
               "Write the loop the role requires: iterate the input the intent names and do the per-item work.",
               "for item in <input>:\n    <per-item work>"),
        # 4b fact (kept, FIX_41): the role requires a call and the body has none — which callee, with what arguments, and what is done with its result must be written; no declared role requires a call today (GETTER return, SETTER params, CONTEXT_MANAGER yield), so the rule cannot fire (uncalled, not a defect) (set 4b-02, 2026-09-10)
    prescribed("HR-006", _HR,
               "Write the call the role requires: invoke the collaborator the intent names with the function's inputs and use its result.",
               "result = collaborator(<inputs>)\nreturn result"),
        # 4b fact (kept, FIX_41): the role requires an assignment and the body has none — what is bound, to which name, and how it is used afterwards must be written; no declared role requires an assignment today, so the rule cannot fire (uncalled, not a defect) (set 4b-02, 2026-09-10)
    prescribed("HR-007", _HR,
               "Write the binding the role requires: assign the computed value to the attribute or local the rest of the body reads.",
               "self.<attr> = <computed from inputs>"),
        # 4b fact (kept, FIX_41): the role requires a comparison and the body has none — what is compared with what, and what follows from the outcome, must be written; no declared role requires a comparison today, so the rule cannot fire (uncalled, not a defect) (set 4b-02, 2026-09-10)
    prescribed("HR-008", _HR,
               "Write the comparison the role requires: compare the input against the intent's threshold or expected value and act on the outcome.",
               "if <input> >= <expected>:   # `>=` stands in for the comparison the role requires (the body has none to read), against the intent's threshold or expected value\n    ..."),
        prescribed("NAI-209", _VM,
               "Make the dependency hard: import it at module top without the fallback and declare it in the project's requirements; when it is genuinely optional, gate every use on the None check and document the degraded behaviour.",
               "import <dependency>"),
    no_fix("NAI-211", _VM, "the except ImportError fallback binds a name the try never imported — the import name, the fallback name, or the fallback itself is wrong, and which one is the dev's intent; the nearest mechanical rewrite (rename the fallback to the imported name) guesses that and only turns this infraction into NAI-209 (set 4b-02, 2026-09-10)"),
        prescribed("NAI-213", "no_aivalidator/noai_validator/validator.py:validate_classes",
               "Write the class body the intent calls for (its attributes, methods or base); an empty class kept as a marker or exception gets a docstring saying so and, for an exception, its base.",
               "class Name(Base):\n    \"\"\"<what it represents>\"\"\"\n    <attributes / methods>"),
        # 4b fact (kept, FIX_41): the module's import count is a published fact, not a construct — which import to drop, and what the code using it becomes, is the dev's intent; a warning on the module row that never reaches the deciding list, so the rule cannot decide today (uncalled, not a defect) (set 4b-03, 2026-09-10)
    prescribed("NAI-215", _VM,
               "Remove the imports the module never uses, and split the module when the remaining count reflects two responsibilities.",
               ""),
        # 4b fact (kept, FIX_41): a module-level list / dict / set is state by design — whether it is mutated, by whom, and what would replace it (an immutable container turns every mutation site into an error) is the dev's intent; a warning on the module row that never reaches the deciding list, so the rule cannot decide today (uncalled, not a defect) (set 4b-03, 2026-09-10)
    prescribed("NAI-216", _VM,
               "Keep module state only where the intent needs a shared registry; otherwise move the container into the class or function that owns it, or make it immutable (a tuple / frozenset, typed Final).",
               "REGISTRY: Final[tuple] = (...)"),
        prescribed("NAI-217", _VM,
               "Import the name X actually defines (fix the spelling), define Y in X, or import from the module that defines Y.",
               "from X import <name X defines>"),
        # 4b fact (kept, FIX_41): `lambda x: x` is either a placeholder for a transformation not yet written or a deliberate default / key; which, and what the transformation should be, is the dev's intent, and removing it changes the call it sits in; a LOW warning on the lambda row the Ranker passes, so the rule cannot decide today (uncalled, not a defect) (set 4b-03, 2026-09-10)
    prescribed("NAI-218", "no_aivalidator/noai_validator/validator.py:validate_lambda",
               "Replace the identity lambda with the transformation the call needs, or drop the argument so the callee's default applies.",
               "key=<the transform>"),
        # 4b fact (kept, FIX_41): `lambda x: 0` ignores its input — a stub for a computation not yet written or a deliberate constant callback; which, and what to compute, is the dev's intent; a MEDIUM warning on the lambda row the Ranker passes, so the rule cannot decide today (uncalled, not a defect) (set 4b-04, 2026-09-10)
    prescribed("NAI-219", "no_aivalidator/noai_validator/validator.py:validate_lambda",
               "Replace the constant lambda with the computation over its argument that the callback's contract expects.",
               "lambda x: <compute from x>"),
        # 4b fact (kept, FIX_41): a call to a name nothing in the module defines, imports, or the builtins hold — the target is unknown, the ground of NAI-050 (which decides the same site and is itself no-fix-by-design); a warning on the function row, never in the deciding list, so the rule cannot decide today (uncalled, not a defect) (set 4b-04, 2026-09-10)
    prescribed("NAI-225", "no_aivalidator/noai_validator/validator.py:_check_cross_function",
               "Define or import the called name (the row's NAI-050 ground): the callee the intent names, with its spelling fixed.",
               "from <module> import <callee>"),
        # 4b fact (kept, FIX_41): eval() of an expression — ast.literal_eval holds only when the argument is a literal, which a line regex cannot know; what the expression should become is the dev's design; the regex scan is not on the daemon's file route (eval is decided there by NAI-160 / NAI-127), so the rule cannot decide today (uncalled, not a defect) (set 4b-04, 2026-09-10)
    prescribed("SEC-001", "no_aivalidator/noai_validator/validator.py:check_vuln_patterns",
               "Replace eval with a parser for the input's actual grammar: `ast.literal_eval` for literals, `json.loads` for JSON, a dispatch table for named operations.",
               "value = ast.literal_eval(text)"),
        # 4b fact (kept, FIX_41): exec() of code — there is no safe substitute that runs the same string; what the code should do without dynamic execution is the dev's design; the regex scan is not on the daemon's file route (exec is decided there by NAI-160 / NAI-127), so the rule cannot decide today (uncalled, not a defect) (set 4b-04, 2026-09-10)
    prescribed("SEC-002", "no_aivalidator/noai_validator/validator.py:check_vuln_patterns",
               "Replace exec with explicit code: a dispatch table of the operations the string can name, or an import of the module it would have defined.",
               "OPS = {\"name\": func}\nOPS[op](*args)"),
        # 4b fact (kept, FIX_41): pickle.load(s) — no drop-in safe deserializer exists; the replacement format (json, a restricted Unpickler) is the dev's choice and changes every producer; the regex scan is not on the daemon's file route (pickle is decided there by NAI-093), so the rule cannot decide today (uncalled, not a defect) (set 4b-04, 2026-09-10)
    prescribed("SEC-003", "no_aivalidator/noai_validator/validator.py:check_vuln_patterns",
               "Replace pickle.load(s) with a format that carries no code: json for plain data, or a restricted Unpickler whose find_class allows only the classes the intent names.",
               "data = json.loads(payload)"),
    rewriter("SEC-004", _VULN, "yaml_safe_load_fix", fix_unsafe_deserialization,
             "alias of NAI-093's rewriter — the regex `yaml.load(x)` with no Loader names the same site; `yaml.load(x)` → `yaml.safe_load(x)`; the regex goes quiet on the rewrite; the scan is off the daemon's route, so live rows decide as NAI-093 (set 4b-05, 2026-09-10)", *_SET5),
    rewriter("SEC-005", _VULN, "subprocess_argv_fix", fix_unsafe_subprocess,
             "alias of NAI-092's rewriter — the regex `shell=True` names the same site; a literal command string becomes an argv list with no shell; the regex goes quiet on the rewrite; the scan is off the daemon's route, so live rows decide as NAI-092 (set 4b-05, 2026-09-10)", *_SET5),
        # 4b fact (kept, FIX_41): `password = '<literal>'` — where the secret should come from (an environment variable and its name, a keyring, a config file) is the dev's design; a rewrite would invent the source; the regex scan is off the daemon's route (the site decides as NAI-072), so the rule cannot decide today (uncalled, not a defect) (set 4b-05, 2026-09-10)
    prescribed("SEC-006", _VULN,
               "Read the password from the environment (or the project's secret store) at the point of use; the literal leaves the source.",
               "password = os.environ[\"<APP>_PASSWORD\"]"),
        # 4b fact (kept, FIX_41): `api_key = '<literal>'` — the same ground as SEC-006: the secret's source must be chosen, not inferred; off the daemon's route (the site decides as NAI-072), so the rule cannot decide today (uncalled, not a defect) (set 4b-05, 2026-09-10)
    prescribed("SEC-007", _VULN,
               "Read the API key from the environment (or the project's secret store) at the point of use; the literal leaves the source.",
               "api_key = os.environ[\"<APP>_API_KEY\"]"),
        # 4b fact (kept, FIX_41): a query built with `.format(...sql...)` — parametrising it means rewriting the query's placeholders AND the execute call's arguments to the driver's paramstyle, which the line does not carry; off the daemon's route (the site decides as NAI-073), so the rule cannot decide today (uncalled, not a defect) (set 4b-05, 2026-09-10)
    prescribed("SEC-008", _VULN,
               "Parametrise the query: placeholders in the driver's paramstyle inside the SQL string, the values passed as execute's second argument.",
               "cur.execute(\"SELECT ... WHERE id = %s\", (user_id,))"),
        # 4b fact (kept, FIX_41): `os.system(cmd)` — an argv subprocess call is not the same call: os.system returns a wait status, runs through the shell by definition and inherits stdio; NAI-092's rewriter refuses it for that reason; what the call should become is the dev's design; off the daemon's route (the site decides as NAI-092), so the rule cannot decide today (uncalled, not a defect) (set 4b-06, 2026-09-10)
    prescribed("SEC-009", _VULN,
               "Replace os.system with `subprocess.run([...], check=True)` on an argv list and read its return code / output explicitly; the shell is not invoked.",
               "subprocess.run([\"cmd\", arg], check=True)"),
    rewriter("SEC-010", _VULN, "subprocess_argv_fix", fix_unsafe_subprocess,
             "alias of NAI-092's rewriter — the regex `subprocess.Popen(... shell=True)` names the same site; a literal command becomes an argv list with no shell; the regex goes quiet on the rewrite; the scan is off the daemon's route, so live rows decide as NAI-092 (set 4b-06, 2026-09-10)", *_SET6),
        # 4b fact (kept, FIX_41): `token / secret / private_key = '<literal>'` — the same ground as SEC-006: where the secret should come from must be chosen, not inferred; off the daemon's route (the site decides as NAI-072), so the rule cannot decide today (uncalled, not a defect) (set 4b-06, 2026-09-10)
    prescribed("SEC-011", _VULN,
               "Read the token / secret / private key from the environment (or the project's secret store) at the point of use; the literal leaves the source.",
               "token = os.environ[\"<APP>_TOKEN\"]"),
        # 4b fact (kept, FIX_41): `__import__(name)` — the static import it should be needs a module name the code does not carry, and `importlib.import_module` is still a dynamic import (and differs on dotted names); the dynamic import is the dev's design; off the daemon's route and decided by no AST rule on the plant, so the rule cannot decide today (uncalled, not a defect) (set 4b-06, 2026-09-10)
    prescribed("SEC-012", _VULN,
               "Replace `__import__(name)` with a static import of each module the intent names, or with `importlib.import_module` over a whitelist of allowed names.",
               "import <module>"),
        # 4b fact (kept, FIX_41): `compile(source, ..., 'exec')` — the same ground as SEC-002: no safe substitute compiles the same string; what the code should do without dynamic execution is the dev's design; off the daemon's route (the site decides as NAI-160), so the rule cannot decide today (uncalled, not a defect) (set 4b-06, 2026-09-10)
    prescribed("SEC-013", _VULN,
               "Replace compile(..., 'exec') with explicit code (the SEC-002 prescription); a plugin system loads modules by name from a whitelist.",
               "module = importlib.import_module(<whitelisted name>)"),
]
