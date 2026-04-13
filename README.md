# Photography AI MCP

> Photo management tools - EXIF analysis, location mapping, duplicate detection, color palettes, metadata editing

Built by **MEOK AI Labs** | [meok.ai](https://meok.ai)

## Features

| Tool | Description |
|------|-------------|
| `analyze_exif` | See tool docstring for details |
| `map_photo_locations` | See tool docstring for details |
| `find_duplicates` | See tool docstring for details |
| `extract_color_palette` | See tool docstring for details |
| `edit_metadata` | See tool docstring for details |

## Installation

```bash
pip install mcp
```

## Usage

### As an MCP Server

```bash
python server.py
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "photography-ai-mcp": {
      "command": "python",
      "args": ["/path/to/photography-ai-mcp/server.py"]
    }
  }
}
```

## Rate Limits

Free tier includes **30-50 calls per tool per day**. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## License

MIT License - see [LICENSE](LICENSE) for details.

---

Built with FastMCP by MEOK AI Labs
