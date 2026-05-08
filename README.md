<div align="center">

# Photography Ai MCP

**Photography AI MCP Server**

[![PyPI](https://img.shields.io/pypi/v/meok-photography-ai-mcp)](https://pypi.org/project/meok-photography-ai-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MEOK AI Labs](https://img.shields.io/badge/MEOK_AI_Labs-MCP_Server-purple)](https://meok.ai)

</div>

## Overview

Photography AI MCP Server
Photo management and analysis tools powered by MEOK AI Labs.

## Tools

| Tool | Description |
|------|-------------|
| `analyze_exif` | Analyze EXIF metadata from an image file (JPEG). |
| `map_photo_locations` | Map and cluster photo locations from GPS coordinates. |
| `find_duplicates` | Find duplicate photos using file hash or metadata comparison. |
| `extract_color_palette` | Extract and analyze a color palette from image color data. |
| `edit_metadata` | Plan metadata edits for a photo file (generates edit commands). |

## Installation

```bash
pip install meok-photography-ai-mcp
```

## Usage with Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "photography-ai": {
      "command": "python",
      "args": ["-m", "meok_photography_ai_mcp.server"]
    }
  }
}
```

## Usage with FastMCP

```python
from mcp.server.fastmcp import FastMCP

# This server exposes 5 tool(s) via MCP
# See server.py for full implementation
```

## License

MIT © [MEOK AI Labs](https://meok.ai)
