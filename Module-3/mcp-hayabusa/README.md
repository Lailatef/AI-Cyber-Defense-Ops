\# mcp-hayabusa



An MCP (Model Context Protocol) server that wraps \[Hayabusa](https://github.com/Yamato-Security/hayabusa), a Sigma-based Windows Event Log (EVTX) analyzer, so Claude can run forensic scans and browse detection rules directly in conversation.



Built as a hands-on exercise in wrapping a CLI security tool as an MCP server, tested end-to-end in both \*\*Claude Code\*\* and \*\*Claude Desktop\*\*.



\## What it does



Two tools are exposed to Claude:



\### `scan\_evtx`

Runs Hayabusa against an EVTX file and returns structured JSON findings.



| Parameter | Description |

|---|---|

| `file\_path` (required) | Path to the EVTX file to scan |

| `severity` | Minimum severity to include: `informational`, `low`, `medium`, `high`, `critical` |

| `rule\_filter` | Substring match against the finding's rule title |

| `output\_format` | `"summary"` (condensed fields) or `"full"` (everything Hayabusa returned) |

| `max\_results` | Cap the number of findings returned |



\### `get\_hayabusa\_rules`

Lists available Hayabusa/Sigma detection rules, so Claude (or you) can see what's detectable before running a scan.



| Parameter | Description |

|---|---|

| `keyword` | Filter rules by substring match against title, description, or tags |

| `max\_results` | Cap the number of rules returned |



\## Example prompts



```

Scan the evtx files at ./samples/ with Hayabusa



What Hayabusa rules are available for detecting credential access?



What Hayabusa rules are available for detecting credential access? Give me the output as a JSON file

```



\## Setup



\*\*Requirements:\*\* Python 3.10+, Windows/macOS/Linux



```bash

git clone https://github.com/YOUR\_USERNAME/mcp-hayabusa.git

cd mcp-hayabusa

pip install -r requirements.txt

```



\*\*Download Hayabusa:\*\*

```bash

chmod +x get\_hayabusa.sh   # macOS/Linux

./get\_hayabusa.sh

```

On Windows, the equivalent is `scripts/download\_hayabusa.py` (detects your platform/arch and pulls the matching release from GitHub automatically).



\*\*Verify it works locally (no MCP client needed):\*\*

```bash

python test\_server.py

```



\## Connecting to Claude Code



This repo already includes `.mcp.json`, which registers the server automatically when you open the project:

```bash

cd mcp-hayabusa

claude

/mcp

```

You should see `hayabusa` listed as connected, with tools `scan\_evtx` and `get\_hayabusa\_rules`.



> \*\*Note:\*\* On some Windows setups, `python` resolves to a non-functional Microsoft Store stub. If so, `.mcp.json` should use `"command": "py"` instead — the Python Launcher for Windows, which works regardless of that issue.



\## Connecting to Claude Desktop



1\. Open Claude Desktop → \*\*Settings → Developer → Edit Config\*\*

2\. Add a `mcpServers` entry pointing to the \*\*full absolute path\*\* of `server.py` (Desktop has no project working directory, unlike Claude Code):

&#x20;  ```json

&#x20;  {

&#x20;    "mcpServers": {

&#x20;      "hayabusa": {

&#x20;        "command": "py",

&#x20;        "args": \["/full/absolute/path/to/mcp-hayabusa/server.py"]

&#x20;      }

&#x20;    }

&#x20;  }

&#x20;  ```

3\. Fully quit Claude Desktop (not just close the window — quit it from the system tray/menu bar) and reopen it.

4\. Check \*\*Settings → Developer\*\* again to confirm `hayabusa` shows as connected.



\### ⚠️ If you installed Claude Desktop from the Microsoft Store



The \*\*"Edit Config"\*\* button in Settings → Developer is the reliable way to find the right file — it opens whichever config Desktop is actually reading. On Store installs, this is \*not\* the commonly documented `%APPDATA%\\Claude\\claude\_desktop\_config.json` path, but a sandboxed location like:

```

%LOCALAPPDATA%\\Packages\\Claude\_<random-id>\\LocalCache\\Roaming\\Claude\\claude\_desktop\_config.json

```

Editing the "standard" path directly does nothing on these installs — Desktop never reads it.



Also: if you edit this file with PowerShell's `Set-Content -Encoding utf8`, it adds a UTF-8 \*\*BOM\*\* (byte-order mark), which can make Claude Desktop fail to launch entirely ("can't load app"). Use `Edit Config` in the app itself, or write the file without a BOM:

```powershell

\[System.IO.File]::WriteAllText($path, $jsonString, (New-Object System.Text.UTF8Encoding($false)))

```



\## Tested against



\- `samples/sysmon\_10\_lsass\_mimikatz\_sekurlsa\_logonpasswords.evtx` — Mimikatz vs. LSASS credential dumping (triggers `high`/`med`/`low` findings)

\- `samples/CA\_DCSync\_4662.evtx` — DCSync attack against a domain controller (triggers `crit` findings)



Both samples originate from \[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).



\## Project structure



```

mcp-hayabusa/

├── server.py              # MCP server: scan\_evtx + get\_hayabusa\_rules

├── test\_server.py          # Manual test harness (no MCP client needed)

├── requirements.txt

├── get\_hayabusa.sh         # Downloads Hayabusa (macOS/Linux)

├── scripts/

│   └── download\_hayabusa.py  # Downloads Hayabusa (cross-platform, stdlib-only)

├── samples/                # Test EVTX fixtures

├── .mcp.json               # Claude Code MCP server registration

└── CLAUDE.md                # Project context for Claude Code

```



`hayabusa/` (the downloaded binary + rules, \~70MB+) is gitignored — run the download script to fetch it locally.



\## The wrapper pattern



This project follows a reusable template for wrapping any CLI tool as an MCP server:



1\. Define tools with clear names, descriptions, and JSON-schema parameters (descriptions matter — Claude uses them to decide when to invoke a tool)

2\. Validate inputs

3\. Build and run the underlying CLI command as a subprocess

4\. Parse its output into structured JSON

5\. Handle errors gracefully — return `{"error": ...}` rather than raising, so Claude can explain what went wrong



The same approach could wrap other DFIR/security tools — Chainsaw, YARA, Volatility, Sigma CLI, CyberChef, etc.

