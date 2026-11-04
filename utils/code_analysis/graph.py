"""
Graph algorithms for dependency and data-flow analysis.

Provides DFS/BFS algorithms, dependency graph construction, and
variable usage analysis.
"""

import logging
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from typing import Optional, TypeVar

from utils.code_analysis.core import DataFlowEdge, FunctionMetrics

logger = logging.getLogger(__name__)

# Type variable for graph nodes
T = TypeVar("T")


def build_dependency_graph(edges: Iterable[tuple[T, T]]) -> dict[T, set[T]]:
    """
    Build an adjacency list graph from a list of edges.

    Args:
        edges: Iterable of (source, target) tuples representing directed edges

    Returns:
        Dictionary mapping each node to a set of its neighbors (outgoing edges)
    """
    graph: dict[T, set[T]] = defaultdict(set)

    for source, target in edges:
        graph[source].add(target)
        # Ensure target exists in graph even if it has no outgoing edges
        if target not in graph:
            graph[target] = set()

    logger.debug("build_dependency_graph: %d nodes", len(graph))
    return dict(graph)


def reverse_graph(graph: dict[T, set[T]]) -> dict[T, set[T]]:
    """
    Reverse all edges in a graph.

    Args:
        graph: The input graph as an adjacency list

    Returns:
        A new graph with all edges reversed
    """
    reversed_graph: dict[T, set[T]] = defaultdict(set)

    # Ensure all nodes exist in reversed graph
    for node in graph:
        if node not in reversed_graph:
            reversed_graph[node] = set()

    # Reverse all edges
    for source, targets in graph.items():
        for target in targets:
            reversed_graph[target].add(source)

    return dict(reversed_graph)


def dfs_reachability(
    graph: dict[T, set[T]],
    starts: set[T],
    targets: set[T],
) -> bool:
    """
    Check if any target node is reachable from any start node using DFS.

    Args:
        graph: The graph as an adjacency list
        starts: Set of starting nodes
        targets: Set of target nodes to find

    Returns:
        True if any target is reachable from any start node
    """
    if not starts or not targets:
        logger.debug("dfs_reachability: empty starts or targets, returning False")
        return False

    # Check if any start is already a target
    if starts & targets:
        logger.debug("dfs_reachability: overlap in starts & targets, returning True")
        return True

    visited: set[T] = set()
    stack: list[T] = list(starts)

    while stack:
        node = stack.pop()

        if node in visited:
            continue

        visited.add(node)

        if node in targets:
            logger.debug("dfs_reachability: reached target %s after visiting %d nodes", node, len(visited))
            return True

        # Add unvisited neighbors to stack
        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                stack.append(neighbor)

    logger.debug("dfs_reachability: exhausted %d nodes, target not found", len(visited))
    return False


def bfs_shortest_path(
    graph: dict[T, set[T]],
    start: T,
    target: T,
) -> Optional[list[T]]:
    """
    Find the shortest path between two nodes using BFS.

    Args:
        graph: The graph as an adjacency list
        start: The starting node
        target: The target node

    Returns:
        List of nodes representing the shortest path, or None if no path exists
    """
    logger.debug("bfs_shortest_path: start=%s target=%s", start, target)
    if start == target:
        return [start]

    if start not in graph:
        return None

    visited: set[T] = {start}
    queue: deque[tuple[T, list[T]]] = deque([(start, [start])])

    while queue:
        node, path = queue.popleft()

        for neighbor in graph.get(node, set()):
            if neighbor == target:
                result = path + [neighbor]
                logger.debug("bfs_shortest_path: found path of length %d", len(result))
                return result

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    logger.debug("bfs_shortest_path: no path found")
    return None


def find_all_paths(
    graph: dict[T, set[T]],
    start: T,
    target: T,
    max_paths: Optional[int] = None,  # EXCISED cut 3 batch 2 (2026-09-06, agreed): was 100
) -> list[list[T]]:
    """
    Find all paths between two nodes (up to a maximum).

    Args:
        graph: The graph as an adjacency list
        start: The starting node
        target: The target node
        max_paths: Maximum number of paths to return (to prevent infinite loops)

    Returns:
        List of paths, where each path is a list of nodes
    """
    if start == target:
        return [[start]]

    if start not in graph:
        return []

    paths: list[list[T]] = []
    stack: list[tuple[T, list[T], set[T]]] = [(start, [start], {start})]

    while stack and (max_paths is None or len(paths) < max_paths):
        node, path, visited = stack.pop()

        for neighbor in graph.get(node, set()):
            if neighbor == target:
                paths.append(path + [neighbor])
            elif neighbor not in visited:
                stack.append((neighbor, path + [neighbor], visited | {neighbor}))

    return paths


def topological_sort(graph: dict[T, set[T]]) -> Optional[list[T]]:
    """
    Perform topological sort on a directed acyclic graph.

    Args:
        graph: The graph as an adjacency list

    Returns:
        List of nodes in topological order, or None if the graph has a cycle
    """
    # Calculate in-degrees
    in_degree: dict[T, int] = defaultdict(int)
    for node in graph:
        if node not in in_degree:
            in_degree[node] = 0
        for neighbor in graph[node]:
            in_degree[neighbor] += 1

    # Start with nodes that have no incoming edges
    queue: deque[T] = deque([node for node, degree in in_degree.items() if degree == 0])
    result: list[T] = []

    while queue:
        node = queue.popleft()
        result.append(node)

        for neighbor in graph.get(node, set()):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    # Check for cycles
    if len(result) != len(in_degree):
        logger.debug("topological_sort: cycle detected, returning None")
        return None

    logger.debug("topological_sort: sorted %d nodes", len(result))
    return result


def find_cycles(graph: dict[T, set[T]]) -> list[list[T]]:
    """
    Find all cycles in a directed graph.

    Uses an iterative DFS to avoid stack overflow on deep graphs.

    Args:
        graph: The graph as an adjacency list

    Returns:
        List of cycles, where each cycle is a list of nodes
    """
    logger.debug("find_cycles: searching %d-node graph", len(graph))
    cycles: list[list[T]] = []
    visited: set[T] = set()
    rec_stack: set[T] = set()

    for start in graph:
        if start in visited:
            continue

        # Stack entries: (node, iterator over neighbors, entered)
        # entered=False means we're visiting for the first time
        path: list[T] = []
        stack: list[tuple[T, Iterator[T], bool]] = [
            (start, iter(graph.get(start, set())), False)
        ]

        while stack:
            node, neighbors, entered = stack[-1]

            if not entered:
                # First visit: mark as visited and on current path
                visited.add(node)
                rec_stack.add(node)
                path.append(node)
                stack[-1] = (node, neighbors, True)

            # Try the next neighbor
            neighbor = next(neighbors, None)

            if neighbor is not None:
                if neighbor not in visited:
                    stack.append(
                        (neighbor, iter(graph.get(neighbor, set())), False)
                    )
                elif neighbor in rec_stack:
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    logger.debug("find_cycles: found cycle %s", cycle)
                    cycles.append(cycle)
            else:
                # All neighbors exhausted — backtrack
                stack.pop()
                path.pop()
                rec_stack.discard(node)

    return cycles


def find_unused_assignments(metrics: FunctionMetrics) -> set[str]:
    """
    Find variables that are assigned but never used.

    Args:
        metrics: The FunctionMetrics object containing variable tracking data

    Returns:
        Set of variable names that are assigned but not used
    """
    # Variables that are assigned but not used (and not parameters)
    assigned = metrics.vars_assigned - metrics.params_declared
    used = metrics.vars_used

    # Find assigned variables that are never used
    unused = assigned - used

    # Exclude common patterns like _ for unused values
    unused = {v for v in unused if not v.startswith("_")}

    # Exclude global/nonlocal declarations — these write to outer scope intentionally
    unused -= getattr(metrics, 'global_vars', set())
    unused -= getattr(metrics, 'nonlocal_vars', set())

    if unused:
        logger.debug("find_unused_assignments: %s has unused vars %s", metrics.name, unused)
    return unused


def find_undefined_uses(metrics: FunctionMetrics) -> set[str]:
    """
    Find variables that are used but never defined.

    This can indicate:
    - Use of global variables
    - Use of built-in functions/names
    - Potential bugs (undefined variables)

    Args:
        metrics: The FunctionMetrics object containing variable tracking data

    Returns:
        Set of variable names that are used but not assigned or declared as parameters
    """
    import builtins as builtins_module

    # All variables that are either assigned or declared as parameters
    defined = metrics.vars_assigned | metrics.params_declared

    # Variables used but not defined locally
    undefined = metrics.vars_used - defined

    # Exclude all built-in names
    builtin_names = set(dir(builtins_module))

    undefined = undefined - builtin_names

    if undefined:
        logger.debug("find_undefined_uses: %s has undefined vars %s", metrics.name, undefined)
    return undefined


def build_data_flow_graph(
    assignments: dict[str, set[str]],
) -> dict[str, set[str]]:
    """
    Build a data flow graph from variable assignments.

    Creates edges from variables used in an assignment to the variable being assigned.

    Args:
        assignments: Dictionary mapping assigned variable names to sets of
                    variable names used in the assignment

    Returns:
        Graph where edges represent data flow dependencies
    """
    graph: dict[str, set[str]] = defaultdict(set)

    for target, sources in assignments.items():
        for source in sources:
            graph[source].add(target)
        # Ensure target exists in graph
        if target not in graph:
            graph[target] = set()

    logger.debug("build_data_flow_graph: %d nodes from %d assignments", len(graph), len(assignments))
    return dict(graph)


def is_identity_chain(metrics: FunctionMetrics) -> bool:
    """Check if all data flow from params to return is identity-preserving.

    A function is an identity chain when:
    1. It has parameters
    2. It has return sources
    3. Every path from a return source back to a parameter consists
       entirely of identity-preserving edges (copies/aliases)
    4. No new data is introduced along any path

    This catches alias-chain fakes like:
        def enrich(data):
            temp = list(data)      # identity: copy_constructor
            processed = temp[:]    # identity: slice_copy
            validated = processed  # identity: direct_assign
            return validated       # all edges identity → FAKE
    """
    if not metrics.params_declared or not metrics.return_sources:
        return False

    if not metrics.data_flow_edges:
        return False

    # Build reverse lookup: target_var -> list of incoming edges
    edges_by_target: dict[str, list[DataFlowEdge]] = defaultdict(list)
    for edge in metrics.data_flow_edges:
        edges_by_target[edge.target].append(edge)

    # Every return source must trace back to a param through identity edges only
    for ret_var in metrics.return_sources:
        if not _trace_identity_to_param(ret_var, metrics.params_declared,
                                         edges_by_target, set()):
            return False

    logger.debug("is_identity_chain: %s — all return sources trace to params via identity ops",
                 metrics.name)
    return True


def _trace_identity_to_param(
    var: str,
    params: set[str],
    edges_by_target: dict[str, list[DataFlowEdge]],
    visited: set[str],
) -> bool:
    """Trace backwards from var to params. True only if every edge is identity."""
    if var in params:
        return True  # Reached a param — chain intact

    if var in visited:
        return False  # Cycle

    visited.add(var)

    incoming = edges_by_target.get(var)
    if not incoming:
        return False  # No incoming edges — var came from external source or literal

    for edge in incoming:
        if edge.operation != "identity":
            return False  # A transform breaks the chain
        if not _trace_identity_to_param(edge.source, params, edges_by_target, visited):
            return False

    return True


if __name__ == "__main__":
    import argparse
    import ast
    import sys
    from pathlib import Path

    # Enable logging for CLI
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Run graph analysis on functions in a Python file."
    )
    parser.add_argument("file", type=Path, help="Python file to analyze")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed analysis for each function"
    )
    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    from utils.code_analysis.extractor import MetricsExtractor, collect_method_ids

    source = args.file.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        print(f"Error: Syntax error in {args.file}: {e}", file=sys.stderr)
        sys.exit(1)

    method_ids = collect_method_ids(tree)
    func_count = 0
    issues_found = 0

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            is_method = id(node) in method_ids
            ext = MetricsExtractor(node, class_context=is_method)
            m = ext.metrics
            func_count += 1

            unused = find_unused_assignments(m)
            undefined = find_undefined_uses(m)
            identity = is_identity_chain(m)

            if args.verbose or unused or undefined:
                print(f"\n{m.name}():")
                if unused:
                    print(f"  unused assignments: {unused}")
                    issues_found += len(unused)
                if undefined:
                    print(f"  undefined uses: {undefined}")
                    issues_found += len(undefined)
                if identity:
                    print(f"  identity chain: True")

                # Build data flow graph if we have edges
                if m.data_flow_edges:
                    edge_tuples = [(e.source, e.target) for e in m.data_flow_edges]
                    g = build_dependency_graph(edge_tuples)
                    cycles = find_cycles(g)
                    if cycles and args.verbose:
                        print(f"  cycles: {cycles}")

    if issues_found == 0:
        print(f"\n✓ No issues found in {func_count} functions in {args.file}")
    else:
        print(f"\n⚠ Found {issues_found} issue(s) in {func_count} functions in {args.file}")
        sys.exit(1)
