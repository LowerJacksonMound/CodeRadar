"""preranker_hunt.py — instance-level hunter (health-check step 17, extended mode; owner list pre-ranker-rankings-hunter-list.txt).
Instance-level hunter for pre-ranker varieties the literal-comparison census cannot see.
Whole tree (no_aivalidator, signature_engine, semantic_analysis, rca_main, system_scripts, detritus_cleaner, utils),
excluding .archive/REFERENCE/.venv and the ranker module itself."""
import ast, glob, os, re, sys, json, collections
ROOT="."; SKIP=("/.archive/","/REFERENCE/","/.venv","/__pycache__/","_removed_rankings","/CODERADAR_RECOVERY/","preranker_hunt.py","preranker_census.py","preranker_ledger_migrate.py","generator_plants")  # generator_plants = planted counterfeits for gate step 19, not engine code (item 4, 2026-09-08); preranker_ledger_migrate.py = the ledger's own maintenance script, the same class as the hunter and the census — the hunter does not hunt its own machinery (tr2_L1, 2026-09-21)
RANKER="cheatsheet_intelligence/knowledge_base.py"
FILES=[f for pat in ("no_aivalidator/**/*.py","signature_engine/**/*.py","semantic_analysis/**/*.py","rca_main/**/*.py","system_scripts/**/*.py","detritus_cleaner/**/*.py","utils/**/*.py") for f in glob.glob(pat,recursive=True) if not any(s in f for s in SKIP) and RANKER not in f]
V=collections.defaultdict(list)
def add(kind,f,node,expr): V[kind].append((f,getattr(node,"lineno",0),expr[:100]))
def u(n): 
    try: return ast.unparse(n)
    except Exception: return "?"
EMIT=re.compile(r"observations\.append|issues\.append|findings\.append|results\.append|warnings\.append|triggered\.append|\.emit\(|report\(")
FLAG=re.compile(r"\b(ENABLE_|DISABLE_|FEATURE_|flags?\.|self\.config\.get\(|config\.get\(|_ENABLED|enable_|disable_|SKIP_|skip_)\w*")
NAMETABLE=re.compile(r"(KNOWN_|SAFE_|ALLOW|DENY|BLACKLIST|WHITELIST|IGNORE|EXEMPT|SUSPICIOUS|STOPWORDS|BOILERPLATE|_NAMES|_WORDS|_PREFIXES|_SUFFIXES|_PATTERNS)\w*", re.I)
class H(ast.NodeVisitor):
    def __init__(s,f,src): s.f=f; s.src=src; s.lines=src.split("\n"); s.fn=[]
    def _enter(s,n): s.fn.append(n); s.generic_visit(n); s.fn.pop()
    visit_FunctionDef=_enter; visit_AsyncFunctionDef=_enter
    def visit_FunctionDef2(s,n): pass
    def visit_arguments(s,n):
        # 26/18b defaulted kwargs that are numeric policy in rule/analysis functions
        for a,d in zip(n.args[len(n.args)-len(n.defaults):]+n.kwonlyargs, n.defaults+[x for x in n.kw_defaults]):
            if d is not None and isinstance(d,ast.Constant) and isinstance(d.value,(int,float)) and not isinstance(d.value,bool) and d.value not in (0,):
                nm=a.arg
                if re.search(r"max|min|limit|top|k$|threshold|thresh|depth|window|budget|cap|ratio|eps|tol|timeout|count|size|n_|num_|width|len",nm,re.I):
                    add("V26 kwarg-default-threshold", s.f, d, f"{s.fn[-1].name if s.fn else '<module>'}({nm}={d.value})")
        s.generic_visit(n)
    def visit_If(s,n):
        t=u(n.test); body=u(n)
        has_emit=bool(EMIT.search(body)); ret=any(isinstance(x,(ast.Return,ast.Continue)) for x in n.body)
        if re.match(r"not \w+(\.\w+)*$",t) and ret and s.fn: add("V18 empty-silence early-out", s.f,n,f"if {t}: return/continue")
        if FLAG.search(t): add("V21 feature-flag / config mute", s.f,n,f"if {t}"[:90])
        if re.search(r"\bin seen\b|\bin _seen\b|\bin visited\b|\bin emitted\b|\bin reported\b|\bin self\._seen",t): add("V20 seen-set gate", s.f,n,f"if {t}")
        if re.search(r"(score|confidence|conf|prob|weight)\s*[<>]=?",t): add("V23 confidence floor/cut", s.f,n,f"if {t}")
        if re.search(r"(depth|level|hops?|distance)\s*[<>]=?\s*\w+",t) and not re.search(r"[<>]=?\s*0\b",t): add("V63 depth/hop cap", s.f,n,f"if {t}")
        if re.search(r"\.(endswith|startswith)\(|\bin \(?['\"]",t) and re.search(r"name|path|file|dir|stem|suffix|module",t): add("V34 name/path table gate", s.f,n,f"if {t}"[:90])
        if re.search(r"isinstance\(",t) and ret and s.fn and has_emit==False and re.search(r"^not isinstance",t): add("V25 isinstance mute (early-out)", s.f,n,f"if {t}")
        if re.search(r"severity|priority|label|band|level\b",t) and re.search(r"==|\bin\b",t) and re.search(r"['\"]",t): add("V47 severity/label string decides", s.f,n,f"if {t}"[:90])
        if re.search(r"baseline|snapshot|previous|prev_|yesterday|golden",t): add("V57 baseline/golden compare decides", s.f,n,f"if {t}"[:90])
        if re.search(r"time|elapsed|deadline|timeout|budget",t) and re.search(r"[<>]",t): add("V28 timeout/budget as verdict", s.f,n,f"if {t}"[:90])
        s.generic_visit(n)
    def visit_Try(s,n):
        for h in n.handlers:
            hb=[type(x).__name__ for x in h.body]
            if hb in (["Pass"],["Return"],["Continue"]) or (len(h.body)==1 and isinstance(h.body[0],ast.Return)):
                if EMIT.search(u(n)) or (s.fn and re.search(r"check|detect|scan|validate|analy|rule|observ|emit",s.fn[-1].name,re.I)):
                    add("V19 exception-swallow around analysis", s.f,h,f"except {u(h.type) if h.type else ''}: {hb[0].lower()}")
        s.generic_visit(n)
    def visit_Call(s,n):
        c=u(n.func)
        if c in ("sorted","max","min") and any(k.arg=="key" for k in n.keywords) and s.fn and not re.search(r"__main__|print|display|format|render|_log",s.fn[-1].name):
            add("V67 sorted/max/min with key (pick or order outside ranker)", s.f,n,u(n)[:90])
        if re.match(r"heapq\.|\.nlargest|\.nsmallest",c): add("V68 heap pick", s.f,n,u(n)[:80])
        if c.endswith("os.environ.get") or c=="os.getenv": add("V27 environment threshold/toggle", s.f,n,u(n)[:80])
        if c.endswith(".get") and n.args and len(n.args)>1 and isinstance(n.args[1],ast.Constant) and isinstance(n.args[1].value,(int,float)) and not isinstance(n.args[1].value,bool) and n.args[1].value!=0:
            add("V5 config/dict-held numeric default", s.f,n,u(n)[:90])
        if c in ("hash","hashlib.md5","hashlib.sha256") : pass
        if re.search(r"random\.|sample\(|shuffle\(",c): add("V65 random/downsample", s.f,n,u(n)[:80])
        if re.search(r"re\.(search|match|fullmatch)$",c) and s.fn and re.search(r"name|ident|vote|type|classif",s.fn[-1].name,re.I): add("V38 regex on names as proof", s.f,n,u(n)[:90])
        s.generic_visit(n)
    def visit_Assign(s,n):
        t=u(n.targets[0]) if n.targets else ""
        if isinstance(n.value,ast.Constant) and isinstance(n.value.value,(int,float)) and not isinstance(n.value.value,bool) and not s.fn and re.search(r"MAX|MIN|LIMIT|THRESH|DEFAULT|CAP|TOP|DEPTH|WINDOW|BUDGET|TIMEOUT|RATIO|WEIGHT|SCORE",t):
            add("V26b module-level numeric policy constant", s.f,n,f"{t} = {n.value.value}")
        if not s.fn and isinstance(n.value,(ast.Set,ast.List,ast.Tuple,ast.Dict)) and NAMETABLE.search(t) and len(getattr(n.value,'elts',getattr(n.value,'keys',[])))>=3:
            add("V34b name/word table (module-level)", s.f,n,f"{t} ({len(getattr(n.value,'elts',getattr(n.value,'keys',[])))} entries)")
        if re.search(r"severity|priority",t,re.I) and isinstance(n.value,ast.Dict) and not s.fn: add("V47b severity/priority map", s.f,n,f"{t} dict")
        if re.search(r"\bweight|coef|alpha|beta|lambda_|decay",t,re.I) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,float): add("V28b fixed coefficient/decay", s.f,n,f"{t} = {n.value.value}")
        if re.search(r"\[0\]$",u(n.value)) and re.search(r"best|top|first|winner|pick|chosen|selected",t,re.I): add("V53 first-hit-wins / index-0 pick", s.f,n,u(n)[:90])
        s.generic_visit(n)
    def _rule_scope(s):
        """I-100 (owner 2026-09-21, run 136 lane D): the ENCLOSING rule function, read over the WHOLE
        stack and not only `s.fn[-1]`. A block nested one level deeper — an inner helper defined inside
        a rule function — used to read `s.fn[-1].name` = the helper's own name, so a gate could be
        SILENCED BY NESTING: `health_check._hc_hr_observation` (3 asserts) and `._hc_runner_presence`
        (10 asserts) are inner functions of `run_health_check`, and every assert in them was invisible
        while the same assert one indent level out was reported. The hunter now sees nested blocks.
        Returns the innermost enclosing rule-named function, or '' if none encloses the node."""
        for x in reversed(s.fn):
            if re.search(r"check|detect|validate|rule|proof|strict",x.name,re.I): return x.name
        return ""
    def visit_Assert(s,n):
        if s.fn and s._rule_scope(): add("V59 assert in analysis path", s.f,n,u(n)[:80])
        s.generic_visit(n)
for f in FILES:
    try: src=open(f).read(); tree=ast.parse(src)
    except Exception as e: V["PARSE-ERROR"].append((f,0,str(e)[:60])); continue
    H(f,src).visit(tree)
# regex-only varieties over raw text
V93_SUPPRESSOR=re.compile(r"#\s*noqa|nolint|type:\s*ignore")
V93_HONOURED=re.compile(r"if |skip|suppress|ignore|continue")
def v93_code_half(l):
    """I-111 (run 131 lane C): V93 is `noqa/suppressor HONOURED` — a suppressor the CODE acts on.
    The pattern was `SUPPRESSOR.search(l) and HONOURED.search(l)`, and the word `ignore` inside
    `# type: ignore` satisfied BOTH halves, so every typing suppressor anywhere on the tree matched
    and was creep until a row was filed for it (171 filed by FIX_54 for that reason alone).
    The honoured half is now read against the line with its suppressor COMMENT removed, so only the
    filed shape — a suppressor sitting on a line that itself skips, continues, ignores or branches —
    matches. Nothing else in the predicate moved."""
    m=V93_SUPPRESSOR.search(l)
    if not m: return l
    h=l.rfind("#",0,m.end())
    return l[:h] if h>=0 else l[:m.start()]
for f in FILES:
    for i,l in enumerate(open(f).read().split("\n"),1):
        if V93_SUPPRESSOR.search(l) and V93_HONOURED.search(v93_code_half(l)) and "NAI-154" not in l: V["V93 noqa/suppressor honoured"].append((f,i,l.strip()[:90]))
        if re.search(r"\bfor .* in .*\[:\s*\d+\]|\bfor .* in .*range\((max_|MAX_|\d{2,})",l): V["V19b iteration cap"].append((f,i,l.strip()[:90]))
        if re.search(r"getsize\(|st_size|MAX_FILE|max_file_size|too (large|big)",l): V["V22 file-size filter"].append((f,i,l.strip()[:90]))
        if re.search(r"lru_cache|@cache\b|_cache\[|memo\[",l) and re.search(r"verdict|result|passed|analy|check",l,re.I): V["V20b memoised verdict"].append((f,i,l.strip()[:90]))

# ── Wave 2 (owner search-for-pre-ranker-rankers.txt: methods 9-14, 30-37, 49, 59-68) ────────────
def wave2(files):
    W=collections.defaultdict(list)
    POLICY=re.compile(r"(MAX|MIN|LIMIT|THRESH|CAP|TOP|DEPTH|WINDOW|BUDGET|TIMEOUT|RATIO|WEIGHT|SCORE|max_|min_|limit|threshold|_k$|topk|cutoff|floor|ceil)",re.I)
    VERD=re.compile(r"^(passed|failed|ok|emit|suppress|suppressed|verdict|status|severity|is_fake|is_counterfeit|flagged|skip|silenced|should_emit|should_fail|accepted|rejected|blocked)$")
    RULEFN=re.compile(r"valid|check|gate|score|rank|repair|proof|detect|analy|classif|identif",re.I)
    consts={}  # (file,NAME)->value  for constant-folding
    for f in files:
        try: src=open(f).read(); tree=ast.parse(src)
        except Exception: continue
        for n in tree.body:
            if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and isinstance(n.value,ast.Constant) and isinstance(n.value.value,(int,float)) and not isinstance(n.value.value,bool):
                consts[(f,n.targets[0].id)]=n.value.value
    for f in files:
        try: src=open(f).read(); tree=ast.parse(src)
        except Exception: continue
        names_here={k[1]:v for k,v in consts.items() if k[0]==f}
        stack=[]
        class W2(ast.NodeVisitor):
            def _e(s,n): stack.append(n); s.generic_visit(n); stack.pop()
            visit_FunctionDef=_e; visit_AsyncFunctionDef=_e; visit_ClassDef=_e
            def fn(s): 
                for x in reversed(stack):
                    if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)): return x.name
                return "<module>"
            def visit_Compare(s,n):
                parts=[n.left]+n.comparators
                if len(n.ops)>1 and any(isinstance(p,ast.Constant) and isinstance(p.value,(int,float)) for p in parts):
                    W["W11 chained compare with literal"].append((f,n.lineno,u(n)[:90]))
                for p in parts:
                    nm=p.id if isinstance(p,ast.Name) else (p.attr if isinstance(p,ast.Attribute) else None)
                    if nm and POLICY.search(nm) and not any(isinstance(q,ast.Constant) for q in parts):
                        W["W9 compare against a NAMED policy value"].append((f,n.lineno,u(n)[:90])); break
                    if nm and nm in names_here:
                        W["W37 constant-folded literal in compare"].append((f,n.lineno,f"{u(n)[:70]}  ({nm}={names_here[nm]})")); break
                if len(n.ops)==1 and isinstance(n.ops[0],(ast.In,ast.NotIn)):
                    rhs=n.comparators[0]; rn=u(rhs)
                    if (isinstance(rhs,(ast.Name,ast.Attribute)) and re.search(r"[A-Z_]{4,}|allow|deny|ignore|skip|exempt|safe|known|table|_set$|_names|_words",rn)) or isinstance(rhs,(ast.Set,ast.Tuple,ast.List)):
                        if RULEFN.search(s.fn()): W["W14 membership-as-gate in a rule function"].append((f,n.lineno,u(n)[:90]))
                s.generic_visit(n)
            def visit_Assign(s,n):
                for t in n.targets:
                    tn=t.id if isinstance(t,ast.Name) else (t.attr if isinstance(t,ast.Attribute) else "")
                    if VERD.match(tn) and isinstance(n.value,(ast.Constant,ast.Compare,ast.BoolOp,ast.UnaryOp)):
                        W["W33 assignment to verdict vocabulary"].append((f,n.lineno,u(n)[:90]))
                s.generic_visit(n)
            def visit_AnnAssign(s,n):
                tn=u(n.target)
                cls=[x for x in stack if isinstance(x,ast.ClassDef)]
                if cls and n.value is not None and isinstance(n.value,ast.Constant) and isinstance(n.value.value,(int,float,bool)) and n.value.value not in (0,) and re.search(r"Config|Requirement|Policy|Settings|Options|Thresh|Limits|Canonical",cls[-1].name):
                    W["W35 policy default on a config/requirements class"].append((f,n.lineno,f"{cls[-1].name}.{tn} = {n.value.value}"))
                s.generic_visit(n)
            def visit_Call(s,n):
                c=u(n.func)
                if c in ("field","Field") and any(k.arg=="default" and isinstance(k.value,ast.Constant) and isinstance(k.value.value,(int,float,bool)) and k.value.value not in (0,False) for k in n.keywords):
                    W["W35b dataclass/pydantic Field default policy"].append((f,n.lineno,u(n)[:90]))
                if re.search(r"json\.load|yaml\.(safe_)?load|toml\.load|tomllib\.load|\.read_text\(",c) and RULEFN.search(s.fn()+" "+f):
                    W["W49 data file loaded into rule/analysis code"].append((f,n.lineno,u(n)[:90]))
                s.generic_visit(n)
            def visit_Subscript(s,n):
                if isinstance(n.slice,ast.Slice):
                    b=[x for x in (n.slice.lower,n.slice.upper) if x is not None]
                    if b and any(isinstance(x,ast.Constant) and isinstance(x.value,int) for x in b) and not (n.slice.lower is None and n.slice.upper is not None and isinstance(n.slice.upper,ast.Constant)):
                        if RULEFN.search(s.fn()): W["W31 slice with literal bound (not [:N]) in a rule function"].append((f,n.lineno,u(n)[:80]))
                s.generic_visit(n)
            def visit_Raise(s,n):
                if RULEFN.search(s.fn()) and n.exc is not None and not re.search(r"NotImplemented|TypeError|ValueError\(f?['\"](invalid|unknown|unsupported)",u(n.exc)):
                    W["W34 raise-as-control in a rule function"].append((f,n.lineno,u(n)[:80]))
                s.generic_visit(n)
            def visit_Return(s,n):
                if isinstance(n.value,ast.BoolOp) and RULEFN.search(s.fn()):
                    W["W32 return of a boolean combination in a rule function"].append((f,n.lineno,u(n)[:90]))
                s.generic_visit(n)
            def visit_Constant(s,n):
                if isinstance(n.value,(int,float)) and not isinstance(n.value,bool) and n.value not in (0,1,-1,2) and RULEFN.search(s.fn()) and s.fn()!="<module>":
                    W["W36 numeric literal inside a rule-named function (any position)"].append((f,n.lineno,f"{s.fn()}: {n.value}"))
        W2().visit(tree)
    # W68 / W49b: numeric keys in data files the app reads
    for df in ["SPECIES_DICT.json","system_scripts/poll_config.json","pyproject.toml"]+glob.glob("no_aivalidator/**/*.json",recursive=True)+glob.glob("system_scripts/*.json"):
        if not os.path.exists(df) or "allowlist" in df or "NOAI_VALIDATION_STATE" in df or "BUILDER_STATE" in df or "circuit_state" in df or "whitelist_" in df or "cb_writes" in df: continue  # BUILDER_STATE = engine output (item 1, 2026-09-08), same class as the other state files
        for i,l in enumerate(open(df,errors="ignore").read().split("\n"),1):
            if re.search(r"\"?(max|min|limit|threshold|size|depth|top|cap|ratio|timeout|interval|weight|score)[a-z_]*\"?\s*[:=]\s*-?\d",l,re.I):
                W["W68 numeric policy in a data/config file"].append((df,i,l.strip()[:90]))
    # W67 apologetic comments
    for f in files:
        for i,l in enumerate(open(f).read().split("\n"),1):
            if re.search(r"#.*\b(heuristic|hack|temporary cap|magic number|FIXME.*(thresh|limit|cap)|tune[d]?\b|arbitrary)",l,re.I):
                W["W67 apologetic comment near policy"].append((f,i,l.strip()[:90]))
    return W
if __name__=="__main__" and "--wave2" in sys.argv:  # delta mode only
    W=wave2(FILES); tot=sum(len(v) for v in W.values())
    prev=json.load(open(sys.argv[1])) if os.path.exists(sys.argv[1]) else {}
    prev_sites={(f,ln) for v in prev.values() for (f,ln,_) in v}
    print(f"wave 2: {tot} candidate sites across {len(W)} new detector kinds")
    for k,v in sorted(W.items(), key=lambda kv:-len(kv[1])):
        new=sum(1 for (f,ln,_) in v if (f,ln) not in prev_sites)
        files=collections.Counter(os.path.basename(x[0]) for x in v)
        print(f"{len(v):4} (new vs wave 1: {new:4})  {k:58} {', '.join(f'{a}({b})' for a,b in files.most_common(3))}")
    json.dump(W, open(sys.argv[1].replace('.json','_wave2.json'),"w"), indent=0)

# ── combined run (default): wave 1 + wave 2, after both are defined ─────────────────────────
if __name__ == "__main__" and "--wave2" not in sys.argv:
    try:
        _W = wave2(FILES)
        for _k, _v in _W.items():
            V[_k].extend(_v)
    except Exception as _e:
        V["WAVE2-ERROR"].append(("preranker_hunt.py", 0, str(_e)[:80]))
    json.dump({k: v for k, v in V.items()}, open(sys.argv[1], "w"), indent=0)
    tot = sum(len(v) for v in V.values())
    print(f"files scanned {len(FILES)} | candidate sites {tot} | varieties hit {len(V)}")
    for k, v in sorted(V.items(), key=lambda kv: -len(kv[1])):
        files = collections.Counter(os.path.basename(x[0]) for x in v)
        print(f"{len(v):4}  {k:52} top files: {', '.join(f'{a}({b})' for a, b in files.most_common(4))}")
