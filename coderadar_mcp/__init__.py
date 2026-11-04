"""coderadar_mcp — the MCP release form of CodeRadar (RELEASE_FORM_MCP_PACKET_2026-09-17).

T1 builds ONLY the interface: `tool_interface` names every tool of packet §B, its input
and output schema, the file it reads or writes, and its one-line contract. No tool is
implemented here — T2 (read tools), T3 (write path) and T4 (session + hand-back) fill the
three lane modules beside this one, in disjoint files.

The interface is stdlib-only by design: nothing in this package imports the engine, so the
proof script runs offline and T1 changes no engine behaviour.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .tool_interface import (  # noqa: F401
    EDGE_STATES,
    HANDLERS,
    OUTCOMES,
    PAGE_SIZE_DEFAULT,
    RETURN_CHANNEL_RECORD,
    SOLUTION_KINDS,
    TOOLS,
    Field,
    ReturnChannelLine,
    ToolSpec,
    register_handler,
    return_channel_line,
    row_id,
    tool,
    validate_payload,
)

__all__ = [
    "EDGE_STATES",
    "HANDLERS",
    "OUTCOMES",
    "PAGE_SIZE_DEFAULT",
    "RETURN_CHANNEL_RECORD",
    "SOLUTION_KINDS",
    "TOOLS",
    "Field",
    "ReturnChannelLine",
    "ToolSpec",
    "__version__",
    "register_handler",
    "return_channel_line",
    "row_id",
    "tool",
    "validate_payload",
]
