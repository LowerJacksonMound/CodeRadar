#!/usr/bin/env bash
cd /Users/dev/Desktop/seven_cities_of_gold
unset PYTHONPATH MCP_TOOL_TIMEOUT
export PYTHONDONTWRITEBYTECODE=1
date '+start %F %T' > /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/seat.times
claude -p "$(cat /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/prompt.txt)" --session-id $(cat /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/sid) \
  --mcp-config /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/cr_mcp.json --strict-mcp-config \
  --allowedTools "mcp__coderadar,mcp__coderadar__*,Edit,Read,Write" --disallowedTools Bash \
  --output-format stream-json --verbose > /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/seat.jsonl 2> /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/seat.err
echo "exit $?" >> /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/seat.times
date '+end %F %T' >> /private/tmp/claude-501/-Users-ian-Desktop-CODE-RADAR-REFURBISH/6ab2f5e2-d3e2-44f4-b89e-4499843e31aa/scratchpad/seatA/seat.times
