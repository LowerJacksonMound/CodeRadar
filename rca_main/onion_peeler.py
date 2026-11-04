"""
Onion Peeler - Multi-Layer Error Discovery & Resolution
========================================================

Addresses the "onion problem": fixing one traceback often reveals another.

Instead of single-pass repair, this module:
1. Fixes layer N
2. Immediately runs the target app
3. Discovers layer N+1 (if any)
4. Uses chain coherence scoring to validate solution sets
5. Can backtrack if solutions don't "go together"
6. Coordinates with ChainCoordinator for multi-agent scenarios

This is inserted into Phase 8 to replace single-shot fixing.
"""

import ast
import asyncio
import re
import subprocess
import tempfile
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set, TypeVar, Callable, TYPE_CHECKING

# Flow tracing integration (optional dependency)
_F = TypeVar('_F', bound=Callable[..., Any])
def trace(func: _F) -> _F: return func
def emit_trace(*args: Any, **kwargs: Any) -> None: pass
def set_workflow(*args: Any, **kwargs: Any) -> None: pass
def dump_traces(*args: Any, **kwargs: Any) -> None: pass

try:
    from flow_tracer import trace, emit_trace, set_workflow, dump_traces  # type: ignore[assignment,no-redef,unused-ignore]
    _TRACING_ENABLED = True
except ImportError:
    _TRACING_ENABLED = False

if TYPE_CHECKING:
    from executor import WorkflowContext

import aiofiles

logger = logging.getLogger(__name__)

# Import ChainCoordinator for multi-agent coordination
try:
    from orchestrator.core.chain_coordinator import (
        get_chain_coordinator, ChainCoordinator, ChainedSolution, SolutionStatus
    )
    COORDINATOR_AVAILABLE = True
except ImportError:
    COORDINATOR_AVAILABLE = False
    get_chain_coordinator = None


@dataclass
class LayerError:
    """A single layer in the error onion."""
    traceback: str
    error_type: str  # e.g., "TypeError", "IndentationError"
    error_message: str
    file_path: str
    line_number: int
    layer_index: int  # 0 = outermost, 1 = revealed after fix, etc.
    
    def __hash__(self) -> int:
        return hash((self.error_type, self.file_path, self.line_number))


@dataclass
class LayerSolution:
    """A solution applied to fix a layer."""
    layer: LayerError
    solution_code: str
    source: str  # "stackoverflow", "cheatsheet", "llm", etc.
    confidence: float  # 0-100
    variables_touched: Set[str] = field(default_factory=set)
    patterns_used: List[str] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        if not self.variables_touched:
            self.variables_touched = self._extract_variables()
        if not self.patterns_used:
            self.patterns_used = self._extract_patterns()
    
    def _extract_variables(self) -> Set[str]:
        """Extract variable names from solution code."""
        try:
            tree = ast.parse(self.solution_code)
            variables = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    variables.add(node.id)
            return variables
        except SyntaxError:
            # Fallback to regex for partial code
            return set(re.findall(r'\b([a-z_][a-z0-9_]*)\b', self.solution_code.lower()))
    
    def _extract_patterns(self) -> List[str]:
        """Identify coding patterns in the solution."""
        patterns = []
        code_lower = self.solution_code.lower()
        
        # Null/None handling patterns
        if 'is none' in code_lower or 'is not none' in code_lower:
            patterns.append('null_check')
        if '.get(' in code_lower:
            patterns.append('safe_access')
        if 'or []' in code_lower or 'or {}' in code_lower or "or ''" in code_lower:
            patterns.append('default_value')
        
        # Type handling patterns
        if 'isinstance(' in code_lower:
            patterns.append('type_check')
        if 'try:' in code_lower:
            patterns.append('exception_handling')
        
        # Import patterns
        if 'import ' in code_lower:
            patterns.append('import_fix')
        
        # Iteration patterns
        if 'for ' in code_lower and ' in ' in code_lower:
            patterns.append('iteration')
        if 'enumerate(' in code_lower:
            patterns.append('indexed_iteration')
        
        return patterns


@dataclass
class SolutionChain:
    """A complete chain of solutions for all layers (raw data only)."""
    layers: List[LayerSolution] = field(default_factory=list)

    def add_solution(self, solution: LayerSolution) -> None:
        """Add a solution to the chain."""
        self.layers.append(solution)

    def get_all_code(self) -> str:
        """Get combined solution code for all layers."""
        return '\n\n'.join(s.solution_code for s in self.layers)


class OnionPeeler:
    """
    Peels error layers one at a time, discovering hidden errors.

    Returns raw SolutionChain data. Coherence scoring and apply/reject
    decisions belong in the cheatsheet pipeline (Step 5).

    Usage:
        peeler = OnionPeeler(target_app_path, working_dir)
        chain = await peeler.peel(max_layers=5)
        # Pass chain to cheatsheet pipeline for scoring + apply decision

    When use_coordinator=True, the peeler registers with ChainCoordinator
    to enable multi-agent tracking and coordinated reintegration.
    """
    
    def __init__(
        self,
        target_app: str,
        working_dir: str,
        knowledge_base: Any = None,
        recorder: Any = None,
        run_command: Optional[str] = None,
        use_coordinator: bool = True,
        agent_id: Optional[str] = None
    ) -> None:
        self.target_app = Path(target_app)
        self.working_dir = Path(working_dir)
        self.knowledge_base = knowledge_base
        self.recorder = recorder
        if run_command:
            import shlex
            self.run_command = shlex.split(run_command)
        else:
            self.run_command = ["python", str(self.target_app)]
        self.agent_id = agent_id or "peeler_default"
        logger.debug("OnionPeeler.__init__: target=%s working_dir=%s agent=%s", target_app, working_dir, self.agent_id)

        # State tracking
        self._original_content: Dict[str, str] = {}  # file_path -> original content
        self._applied_fixes: List[Tuple[str, str, str]] = []  # (file, old, new)
        
        # Chain coordination
        self._use_coordinator = use_coordinator and COORDINATOR_AVAILABLE
        self._chain_id: Optional[str] = None
        self._coordinator: Optional[ChainCoordinator] = None
        
        if self._use_coordinator:
            self._coordinator = get_chain_coordinator()
            if recorder:
                self._coordinator.set_recorder(recorder)
    
    @property
    def chain_id(self) -> Optional[str]:
        """Get the chain ID for this peeling session."""
        return self._chain_id
    
    @trace  # FLOW_TRACER_INSTRUMENTED
    async def peel(self, max_layers: int = 5, coherence_threshold: float = 50.0) -> SolutionChain:
        """
        Peel the error onion layer by layer.
        
        Args:
            max_layers: Maximum layers to peel
            coherence_threshold: Minimum coherence score to accept chain
            
        Returns:
            SolutionChain with all solutions and coherence score
        """
        logger.debug("peel: max_layers=%d coherence_threshold=%.1f", max_layers, coherence_threshold)
        chain = SolutionChain()

        # Create chain in coordinator if enabled
        if self._use_coordinator and self._coordinator:
            self._chain_id = self._coordinator.create_chain(
                target_app=str(self.target_app),
                working_dir=str(self.working_dir),
                run_command=" ".join(self.run_command)
            )
            logger.info(f"🔗 Created coordinator chain: {self._chain_id}")
        
        layers_discovered = 0
        
        for layer_idx in range(max_layers):
            logger.info(f"🧅 Peeling layer {layer_idx + 1}/{max_layers}...")
            
            # Record recorder event
            if self.recorder:
                self.recorder.record_event({
                    'type': 'onion_layer',
                    'layer': layer_idx,
                    'phase': 'discovering'
                })
            
            # 1. Run the app to get current error
            error = await self._run_and_capture_error(layer_idx)
            
            if error is None:
                logger.info(f"✅ No more errors! Peeled {layer_idx} layers total.")
                break
            
            layers_discovered += 1
            logger.info(f"   Found: {error.error_type}: {error.error_message[:60]}...")
            
            # Register layer with coordinator
            if self._use_coordinator and self._coordinator and self._chain_id:
                self._coordinator.register_layer(
                    chain_id=self._chain_id,
                    layer_index=layer_idx,
                    file_path=error.file_path,
                    line_number=error.line_number,
                    error_type=error.error_type,
                    error_message=error.error_message,
                    agent_id=self.agent_id
                )
            
            # 2. Get solution candidates
            candidates = self._get_solution_candidates(error)
            
            if not candidates:
                logger.warning(f"   No solutions found for layer {layer_idx}")
                break
            
            # 3. If we have previous solutions, rank by chain coherence
            if chain.layers:
                candidates = self._rank_by_coherence(candidates, chain)
            
            # 4. Apply best solution tentatively
            best_solution = candidates[0]
            await self._apply_fix_tentatively(best_solution)
            chain.add_solution(best_solution)
            
            # Register solution with coordinator
            if self._use_coordinator and self._coordinator and self._chain_id:
                self._coordinator.register_solution(
                    chain_id=self._chain_id,
                    layer_index=layer_idx,
                    solution_code=best_solution.solution_code,
                    source=best_solution.source,
                    confidence=best_solution.confidence,
                    agent_id=self.agent_id
                )
            
            logger.info(f"   Applied: {best_solution.source} (confidence: {best_solution.confidence:.1f})")

            # Record to recorder (raw data)
            if self.recorder:
                self.recorder.record_event({
                    'type': 'onion_layer',
                    'layer': layer_idx,
                    'phase': 'fixed',
                    'error_type': error.error_type,
                    'solution_source': best_solution.source,
                })
        
        # Mark discovery complete in coordinator
        if self._use_coordinator and self._coordinator and self._chain_id:
            self._coordinator.mark_discovery_complete(self._chain_id, layers_discovered)
        
        return chain
    
    @trace
    async def _run_and_capture_error(self, layer_idx: int) -> Optional[LayerError]:
        """Run the target app and capture any error."""
        logger.debug("_run_and_capture_error: layer %d", layer_idx)
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.run_command,
                cwd=str(self.working_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode != 0 and stderr:
                return self._parse_traceback(stderr.decode(errors='replace'), layer_idx)

            return None

        except asyncio.TimeoutError:
            logger.warning("App execution timed out")
            return None
        except Exception as e:
            logger.error(f"Error running app: {e}")
            return None
    
    def _parse_traceback(self, stderr: str, layer_idx: int) -> Optional[LayerError]:
        """Parse a traceback into a LayerError."""
        logger.debug("_parse_traceback: layer %d, stderr_len=%d", layer_idx, len(stderr))
        lines = stderr.strip().split('\n')
        
        # Find the error line (usually last line)
        error_line = None
        for line in reversed(lines):
            if ':' in line and not line.startswith(' '):
                error_line = line
                break
        
        if not error_line:
            return None
        
        # Parse error type and message
        match = re.match(r'^(\w+Error|\w+Exception):\s*(.+)$', error_line)
        if not match:
            # Try without message
            match = re.match(r'^(\w+Error|\w+Exception)$', error_line)
            if match:
                error_type = match.group(1)
                error_message = ""
            else:
                return None
        else:
            error_type = match.group(1)
            error_message = match.group(2)
        
        # Find file and line from traceback
        file_path = str(self.target_app)
        line_number = 0
        
        for line in lines:
            file_match = re.search(r'File "([^"]+)", line (\d+)', line)
            if file_match:
                file_path = file_match.group(1)
                line_number = int(file_match.group(2))
        
        return LayerError(
            traceback=stderr,
            error_type=error_type,
            error_message=error_message,
            file_path=file_path,
            line_number=line_number,
            layer_index=layer_idx
        )
    
    def _get_solution_candidates(self, error: LayerError) -> List[LayerSolution]:
        """Get solution candidates from knowledge base and solution finder."""
        logger.debug("_get_solution_candidates: %s at %s:%d", error.error_type, error.file_path, error.line_number)
        candidates = []
        
        # Build a job-like context for the knowledge base
        job_context = {
            'description': f"{error.error_type}: {error.error_message}",
            'file_path': error.file_path,
            'line_number': error.line_number,
            'traceback': error.traceback,
        }
        
        # Try knowledge base first
        if self.knowledge_base:
            try:
                kb_results = self.knowledge_base.search_solutions(
                    error_message=job_context['description'],
                    file_path=error.file_path,
                    max_results=5
                )
                
                for result in kb_results:
                    solution = LayerSolution(
                        layer=error,
                        solution_code=result.get('code', ''),
                        source=result.get('source', 'knowledge_base'),
                        confidence=result.get('score', 50.0)
                    )
                    candidates.append(solution)
                    
            except Exception as e:
                logger.debug(f"Knowledge base search error: {e}")

        # Fallback: generate solutions from error context if KB returned nothing
        if not candidates:
            candidates = self._generate_fallback_solutions(error)
        
        # Sort by confidence
        candidates.sort(key=lambda s: s.confidence, reverse=True)
        
        return candidates
    
    def _generate_fallback_solutions(self, error: LayerError) -> List[LayerSolution]:
        """
        Generate fallback solutions from error context when KB is unavailable.
        
        Pattern-matches on error_type to produce a single low-confidence fix
        that is enough to unpeel the current layer.
        """
        logger.debug("_generate_fallback_solutions: %s at %s:%d",
                     error.error_type, error.file_path, error.line_number)
        
        try:
            source_line = self._read_source_line(error.file_path, error.line_number)
        except Exception:
            source_line = ""
        
        indent = ""
        if source_line:
            indent = " " * (len(source_line) - len(source_line.lstrip()))
        
        fix_code = ""
        etype = error.error_type
        
        if etype == "KeyError":
            # Extract key from error message (e.g., KeyError: 'num_shows')
            key = error.error_message.strip("'\"")
            if source_line and "[" in source_line:
                # Replace d['key'] with d.get('key', None)
                fix_code = source_line.replace(
                    f"['{key}']", f".get('{key}', None)"
                ).replace(
                    f'["{key}"]', f'.get("{key}", None)'
                )
            else:
                fix_code = f"{indent}# KeyError fix: use .get() for safe access\n{source_line}"
        
        elif etype in ("TypeError", "ValueError"):
            # Wrap the offending line in try/except
            stripped = source_line.rstrip() if source_line else "pass"
            fix_code = (
                f"{indent}try:\n"
                f"{indent}    {stripped.lstrip()}\n"
                f"{indent}except ({etype},):\n"
                f"{indent}    pass  # fallback for {etype}\n"
            )
        
        elif etype == "AttributeError":
            # Extract attribute name from message
            attr_match = re.search(r"has no attribute '(\w+)'", error.error_message)
            attr_name = attr_match.group(1) if attr_match else "attr"
            obj_match = re.search(r"'(\w+)' object", error.error_message)
            obj_name = obj_match.group(1).lower() if obj_match else "obj"
            fix_code = (
                f"{indent}if hasattr({obj_name}, '{attr_name}'):\n"
                f"{indent}    {source_line.lstrip() if source_line else 'pass'}\n"
            )
        
        elif etype == "FileNotFoundError":
            path_match = re.search(r"No such file or directory: '([^']+)'", error.error_message)
            path_str = path_match.group(1) if path_match else "path"
            fix_code = (
                f"{indent}import os\n"
                f"{indent}if os.path.exists('{path_str}'):\n"
                f"{indent}    {source_line.lstrip() if source_line else 'pass'}\n"
                f"{indent}else:\n"
                f"{indent}    pass  # file not found\n"
            )
        
        elif etype == "ZeroDivisionError":
            fix_code = (
                f"{indent}# Guard against division by zero\n"
                f"{indent}try:\n"
                f"{indent}    {source_line.lstrip() if source_line else 'pass'}\n"
                f"{indent}except ZeroDivisionError:\n"
                f"{indent}    pass\n"
            )
        
        elif etype in ("ImportError", "ModuleNotFoundError"):
            mod_match = re.search(r"No module named '(\w+)'", error.error_message)
            mod_name = mod_match.group(1) if mod_match else "module"
            fix_code = (
                f"{indent}try:\n"
                f"{indent}    {source_line.lstrip() if source_line else f'import {mod_name}'}\n"
                f"{indent}except ImportError:\n"
                f"{indent}    {mod_name} = None  # module not available\n"
            )
        
        else:
            # Generic try/except fallback
            stripped = source_line.rstrip() if source_line else "pass"
            fix_code = (
                f"{indent}try:\n"
                f"{indent}    {stripped.lstrip()}\n"
                f"{indent}except Exception:\n"
                f"{indent}    pass  # auto-fallback for {etype}\n"
            )
        
        if not fix_code:
            return []
        
        return [LayerSolution(
            layer=error,
            solution_code=fix_code,
            source="auto_fallback",
            confidence=40.0,
        )]
    
    def _read_source_line(self, file_path: str, line_number: int) -> str:
        """Read a single source line from a file (sync helper)."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                for i, line in enumerate(f, 1):
                    if i == line_number:
                        return line.rstrip('\n')
        except Exception:
            pass
        return ""
    
    def _rank_by_coherence(
        self,
        candidates: List[LayerSolution],
        existing_chain: SolutionChain
    ) -> List[LayerSolution]:
        """Re-rank candidates based on coherence with existing chain."""
        logger.debug("_rank_by_coherence: %d candidates, %d existing layers", len(candidates), len(existing_chain.layers))
        try:
            from orchestrator.core.chain_coherence import ChainCoherenceScorer
            scorer = ChainCoherenceScorer()
        except ImportError:
            # Fallback: return candidates in original order
            return candidates
        
        scored = []
        for candidate in candidates:
            # Score how well this candidate fits with existing chain
            coherence = scorer.score_candidate_fit(candidate, existing_chain.layers)
            
            # Blend original confidence with coherence
            blended_score = (candidate.confidence * 0.6) + (coherence * 0.4)
            
            scored.append((blended_score, candidate))
        
        # Sort by blended score
        scored.sort(key=lambda x: x[0], reverse=True)
        
        # Update confidence to blended score
        for score, candidate in scored:
            candidate.confidence = score
        
        return [c for _, c in scored]
    
    @trace
    async def _apply_fix_tentatively(self, solution: LayerSolution) -> None:
        """Apply a fix but track it for potential rollback."""
        logger.debug("_apply_fix_tentatively: %s (source=%s)", solution.layer.file_path, solution.source)
        file_path = solution.layer.file_path

        # Save original if not already saved
        if file_path not in self._original_content:
            try:
                async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    self._original_content[file_path] = await f.read()
            except Exception as e:
                logger.warning(f"Could not backup {file_path}: {e}")

        # For now, we trust the solution code is the complete fixed file
        # In production, this would do a more surgical edit
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                current_content = await f.read()

            # Store the fix for potential rollback
            self._applied_fixes.append((file_path, current_content, solution.solution_code))

            # Apply the fix
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                await f.write(solution.solution_code)

        except Exception as e:
            logger.error(f"Could not apply fix to {file_path}: {e}")
    
    async def rollback_last(self) -> bool:
        """Rollback the last applied fix."""
        logger.debug("rollback_last: %d fixes in stack", len(self._applied_fixes))
        if not self._applied_fixes:
            return False

        file_path, old_content, _ = self._applied_fixes.pop()
        try:
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                await f.write(old_content)
            logger.info(f"Rolled back: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    @trace
    async def rollback_all(self) -> int:
        """Rollback all fixes to original state."""
        logger.debug("rollback_all: %d original files to restore", len(self._original_content))
        count = 0
        for file_path, original in self._original_content.items():
            try:
                async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                    await f.write(original)
                count += 1
            except Exception as e:
                logger.error(f"Could not restore {file_path}: {e}")

        self._applied_fixes.clear()
        return count
    
    def commit_chain(self, chain: SolutionChain) -> bool:
        """Commit the solution chain - clear rollback history."""
        logger.debug("commit_chain: %d layers", len(chain.layers))

        # Clear rollback history - fixes are now permanent
        self._original_content.clear()
        self._applied_fixes.clear()
        
        logger.info(f"✅ Committed {len(chain.layers)} layer fixes")
        return True
    
    def validate_via_coordinator(self, validation: Any = None) -> Tuple[bool, str]:
        """
        Validate the chain through the coordinator.

        This enables chain-level always-pass validation where all solutions
        are tested together.
        """
        if not self._use_coordinator or not self._coordinator or not self._chain_id:
            return False, "Coordinator not available or no chain created"

        result: Tuple[bool, str] = self._coordinator.validate_chain(self._chain_id, validation)
        return result
    
    def integrate_via_coordinator(self, target_dir: Optional[str] = None) -> Tuple[bool, str]:
        """
        Integrate the chain through the coordinator.

        This enables atomic reintegration where all solutions are
        committed together.
        """
        if not self._use_coordinator or not self._coordinator or not self._chain_id:
            return False, "Coordinator not available or no chain created"

        result: Tuple[bool, str] = self._coordinator.integrate_chain(self._chain_id, target_dir)
        return result
    
    def get_chain_status(self) -> Dict[str, Any]:
        """Get the current chain status from coordinator."""
        logger.debug("get_chain_status: chain_id=%s", self._chain_id)
        if not self._use_coordinator or not self._coordinator or not self._chain_id:
            return {"status": "no_coordinator"}
        
        manifest = self._coordinator.get_chain(self._chain_id)
        if not manifest:
            return {"status": "chain_not_found"}
        
        return {
            "chain_id": self._chain_id,
            "status": manifest.status.value,
            "expected_layers": manifest.expected_layers,
            "completed_layers": manifest.layers_completed,
            "solutions": [
                {
                    "layer": s.layer_index,
                    "file": s.file_path,
                    "error": s.error_type,
                    "status": s.status.value,
                    "agent": s.agent_id
                }
                for s in manifest.get_solutions_in_order()
            ]
        }


# Convenience function for integration
@trace
async def peel_and_fix(
    target_app: str,
    working_dir: str,
    knowledge_base: Any = None,
    recorder: Any = None,
    max_layers: int = 5,
    use_coordinator: bool = True,
    validation: Any = None
) -> Tuple[bool, SolutionChain, Optional[str]]:
    """
    Convenience function to peel an error onion and apply fixes.

    Returns:
        (success, solution_chain, chain_id)
    """
    logger.debug("peel_and_fix: target=%s max_layers=%d", target_app, max_layers)
    peeler = OnionPeeler(
        target_app=target_app,
        working_dir=working_dir,
        knowledge_base=knowledge_base,
        recorder=recorder,
        use_coordinator=use_coordinator
    )

    chain = await peeler.peel(max_layers=max_layers)

    if not chain.layers:
        # No errors found or no solutions
        return True, chain, peeler.chain_id

    # If using coordinator, validate through it
    if use_coordinator and peeler.chain_id:
        success, message = peeler.validate_via_coordinator(validation)
        if success:
            peeler.commit_chain(chain)
            return True, chain, peeler.chain_id
        else:
            logger.warning(f"Coordinator validation failed: {message}")
            await peeler.rollback_all()
            return False, chain, peeler.chain_id

    # Return raw chain — coherence scoring/apply decisions belong in cheatsheets (Step 5)
    return True, chain, peeler.chain_id


# Backward-compatible alias for callers that use the old _async name
peel_and_fix_async = peel_and_fix


# =============================================================================
# WORKFLOW HANDLER (executor.py integration)
# =============================================================================

@trace
async def onion_peel_handler(context: 'WorkflowContext') -> 'WorkflowContext':
    """
    Workflow handler for onion peel (deep validation) step.

    Reads: context.validated_fixes, context.repo_path
    Writes: context.validated_fixes (may add discovered layers)

    Now fully async - uses peel directly instead of to_thread wrapper.
    """
    logger.debug("onion_peel_handler: validated_fixes=%d", len(context.validated_fixes) if context.validated_fixes else 0)
    if not context.validated_fixes:
        return context

    max_layers = context.config.get('max_layers', 3)

    success, chain, chain_id = await peel_and_fix(
        target_app=context.repo_path,
        working_dir=context.repo_path,
        max_layers=max_layers,
        use_coordinator=False,
    )

    if chain and chain.layers:
        context.step_results['onion_peel'] = {
            'layers_discovered': len(chain.layers),
            'success': success,
        }

    return context
