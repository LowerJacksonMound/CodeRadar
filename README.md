# CodeRadar

**Deterministic, real-time detection and autonomous repair of counterfeit code in AI-assisted development.**

---

## The Problem

The software industry has no consensus term for this phenomenon. It has been called hallucination, code drift, AI slop, reward hacking. This project uses **counterfeit code** because it is the most precise description: code that *misrepresents what it does*.

Counterfeit code:
- Parses without errors
- Passes linting and type checking
- Looks logically sound to a human reviewer
- **Violates mathematical invariants that real implementations must satisfy**

It is not broken code. Broken code throws errors. Counterfeit code *runs*. It just doesn't do what it claims.

### The Difficulty-Scale Curve

AI agent reliability degrades along two axes simultaneously: **task difficulty** and **codebase size**.

- **Easy task + small codebase** → low counterfeit risk
- **Hard task + large codebase** → **high counterfeit risk**

This creates a paradox: **developers reach for AI assistance precisely when the task is hard and the codebase is large — and that is precisely when the output is least trustworthy.** Without a validation layer, there is no way to distinguish real implementations from counterfeit ones.

No developer can keep pace with the volume of code an AI agent generates. An agent can produce hundreds of lines across dozens of files in minutes. Reading every line negates the speed advantage. Not reading every line means trusting output that becomes less trustworthy as tasks get harder and codebases get larger.

CodeRadar validates at agent speed — deterministically, mathematically, in real time.

---

## What Counterfeit Code Looks Like

Every one of these passes `mypy`, passes `ruff`, passes `ast.parse()`. None does what its name and signature promise.

**Identity function** — accepts input, ignores it, returns the input unchanged:
```python
def calculate_discount(price, percentage):
    result = price * percentage / 100  # dead computation
    return price                        # returns input unchanged
```

**Mutation theater** — creates local state, mutates it, returns the original:
```python
def sanitize_records(records):
    cleaned = []
    for r in records:
        cleaned.append(r.strip().lower())
    return records  # returns original, not cleaned
```

**Dead computation** — calculates values that are never used:
```python
def process_batch(items):
    total = sum(item.value for item in items)
    average = total / len(items)
    filtered = [i for i in items if i.active]
    return items  # total, average, filtered all discarded
```

---

## The Four Invariants

CodeRadar enforces four mathematical invariants that all legitimate implementations must satisfy:

1. **Inputs must influence outputs** — every parameter must reach at least one return value through the data flow graph
2. **Computation must be captured** — assigned variables must be read; calculated values must be used
3. **Iteration must accumulate** — loops must build state across iterations, not overwrite on each pass
4. **Functions must produce** — every function must have either return values or side effects

Violating any one is sufficient proof of counterfeit code. No probabilistic judgment required.

---

## Architecture

Three coordinated daemons communicating through file-locked JSON state:

```
Developer edits Python file
        │
        ▼ filesystem event (<1s)
┌──────────────────────────┐
│  CIRCUIT_DAEMON           │
│  Watchdog + AST scanner   │
│  mypy + CRC fingerprint   │
│  ──► circuit_state.json   │
└──────────┬───────────────┘
           ▼ change detected
┌──────────────────────────┐
│  NOAI_VALIDATOR_DAEMON    │
│  5-stage pipeline         │
│  97+ discrete predicates  │
│  ──► NOAI_VALIDATION_     │
│      STATE.json           │
│  ──► .noai_state.json     │
│      (mirror → all dirs)  │
└──────────┬───────────────┘
           ▼ results ready
┌──────────────────────────┐
│  PROOF_DASHBOARD          │
│  Web UI @ :8080           │
│  Circuit graph + findings │
│  + repair cheatsheets     │
└──────────────────────────┘
```

Startup is completion-gated: CIRCUIT_DAEMON must reach `READY` before VALIDATOR starts; VALIDATOR must complete baseline before DASHBOARD renders. After initialization, validation is incremental — only changed files are re-analyzed, yielding sub-second validation for individual edits.

---

## Detection: Two-Layer Binary System

### Layer 1: Hard Requirements
Pure boolean structural predicates. Any single violation is an immediate `FAIL`.

Does the function have a return or side effect? Are all parameters referenced? Is the body more than `pass`?

### Layer 2: AI Fake Detector (97+ Rules)

| Category | NAI Codes | Detects |
|---|---|---|
| Core | 002–025 | Dead computation, identity functions, unreachable code |
| Structural | 026–029 | Identical branches, mutation theater |
| Mathematical | 030–039 | Data flow disconnect, dead stores, algebraic identity |
| Advanced | 040–049 | Subtree duplication, closure anomalies |
| Hallucination | 050–058 | Invented imports, misspelled builtins, undefined calls |
| Redundancy | 060–069 | Double negation, boolean identity |
| Safety | 070–089 | Bare except, mutable defaults, hardcoded secrets |
| Style | 090–099 | Generic naming, excessive nesting |
| Semantic | 100–119 | Name/behavior mismatch, parameter disconnect |
| Extended Semantic | 120–180 | Verb-operation mapping, deep semantic analysis |

Every check is a discrete predicate: `P(AST) → {True, False}`. No scores. No thresholds. No confidence percentages.

---

## Mathematical Methods

- **Data Flow Reachability** — directed graph `G = (V, E)`, backward DFS from output sources. If any declared parameter is not in the reachable set and the function has return statements, counterfeit signature confirmed.
- **Dead Store Detection** — set difference `W − R` (written minus read). Variables assigned but never read are computed for nothing.
- **AST Structural Hashing** — MD5 of `ast.dump()` with `include_attributes=False`. Hash equality between `if` and `else` bodies is mathematical proof the condition is meaningless.
- **Statistical Outlier Detection** — known-good sample mean `μ` and std `σ`. AI-generated functions outside `[μ − 2σ, μ + 2σ]` per metric are flagged.
- **Cyclomatic Complexity** — `C = 1 + B + L`. A function named "validate" with `C ≤ 2` cannot validate anything.
- **Algebraic Identity Detection** — AST pattern matching on `BinOp` nodes catches `x + 0`, `x * 1` and similar no-op arithmetic.
- **Tautology Detection** — `ast.dump(left) = ast.dump(comparator)` proves a comparison is statically determined.

---

## Why No-AI Validation Is the Only Correct Approach

Using AI to validate AI-generated code reintroduces the exact failure mode you are trying to detect.

| | AI-Based Validator | CodeRadar |
|---|---|---|
| Same input, same output? | No — stochastic | Yes — deterministic |
| Can hallucinate "pass"? | Yes | No |
| Requires API / internet? | Yes | No |
| Cost per validation | tokens × price | 0 |
| Latency | seconds to minutes | milliseconds |
| Auditable reasoning? | Opaque | Fully traceable |
| Version drift risk? | High | None |

---

## The Live Circuit Graph

CodeRadar's dashboard renders a live circuit graph — every file, its import connections, its validation status — updated in real time. When an agent edits a file:

- Connections dropping from a module are visible the instant they happen — nodes go red
- Circular dependencies appear as highlighted cycles  
- Syntax errors surface as broken nodes immediately

A real example: an agent was editing so quickly it severed all connections from `__init__` — every downstream import broke. The circuit graph showed nodes going red in real time. The developer interrupted the agent at that exact moment. Without the visual, this would have been discovered days later with layers of additional counterfeit code built on top.

---

## Demo

**[Watch the demo on YouTube](https://youtu.be/J82pCGun2dk)**

Shows: daemon startup, live circuit graph state transitions, NoAI validator firing with NAI codes and specific fixes, OnionPeeler RCA tracing, remediation cycle, graph returning to green.

---

## Technical Report

For a full description of the architecture, mathematical methods, repair pipeline, cross-file forensics, and design rationale:

**[CODERADAR_TECHNICAL_REPORT.md](./CODERADAR_TECHNICAL_REPORT.md)**

---

## Current Status

- Python codebases — **fully supported**
- Additional language support — in progress (framework is in place; per-language AST adapters are the remaining work)
- Core dependencies: `aiofiles`; dashboard adds `dash`, `plotly`, `networkx`
- No API keys. No cloud. No token budget. Runs fully offline.

Built by one person. Closed source for now.

---

## Contact

GitHub: [@LowerJacksonMound](https://github.com/LowerJacksonMound)
