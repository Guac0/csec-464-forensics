# Forensics Tool — AI-Assisted Memory Forensics (Proof of Concept)

A browser-based interface for analysing Windows RAM images with
[volatility3](https://github.com/volatilityfoundation/volatility3), with an external AI model
that helps interpret the output and suggests what to run next.

## Intent

Volatility is powerful but hard to drive from the command line: plugin names and flags are easy to
get wrong, output is large, and it is hard to keep track of what was run and what it showed. This
project wraps it in a local web app so an analyst can:

- pick a RAM image and run volatility plugins from a guided form instead of the CLI,
- browse, filter and keep every result, with the exact command, tool version and hashes recorded,
- keep investigation notes next to the evidence,
- ask an AI assistant questions about the results, where every claim cites the specific result
  rows it relies on and the full prompt/model/parameters are recorded,
- run the follow-up queries the AI suggests with one click, after they pass the same argument
  allowlist as manual queries.

**AI output is a lead, never evidence.** It is always shown separately from tool output and must be
verified against the cited rows.

This is a deliberately small proof of concept: **single user, runs on your own workstation, bound to
`127.0.0.1`, no login.** See [basic_version_notes.md](basic_version_notes.md) for the design and
[CONTRACTS.md](CONTRACTS.md) for the code structure.

## Running it

**Requirements:** Docker Desktop (Windows/macOS) or Docker Engine with Compose v2.24+ (Linux), and
an OpenAI-compatible AI endpoint (e.g. a local Ollama/vLLM server or an approved hosted provider).

1. **Configure** (optional but needed for AI features):

   ```bash
   cp .env.example .env
   # edit FT_AI_BASE_URL, FT_AI_API_KEY, FT_AI_MODEL
   ```

2. **Add evidence:** copy RAM images into the `evidence/` folder. It is mounted read-only into the
   container and ignored by git as images are typically too large to version control and vary based on the user's needs.

3. **Start:**

   ```bash
   docker compose up --build
   ```

4. **Open** <http://127.0.0.1:8000> and click **Scan evidence folder**.

Stop with `Ctrl+C` or `docker compose down`. Your work (database, run output, symbol cache) is kept
in Docker volumes between restarts; `docker compose down -v` deletes it all. Logs:
`docker compose logs -f app`.

### Windows / Docker Desktop tips

- Keep the repo and `evidence/` inside the WSL2 filesystem (e.g. `\\wsl$\Ubuntu\home\<you>\...`).
  Mounting multi-GB images from `C:\` is very slow.
- Give WSL enough memory for large images in `%UserProfile%\.wslconfig` (`[wsl2]` /
  `memory=12GB`), then `wsl --shutdown`. The container limit is `FT_MEM_LIMIT` (default `8g`).
- volatility downloads Windows symbols from Microsoft the first time it sees a Windows build, so the
  first run needs internet. Symbols are cached afterwards; set `FT_VOL_OFFLINE=true` to forbid
  downloads.
- An AI server on the Windows host is reachable from the container at
  `http://host.docker.internal:<port>/v1`, not `localhost`.

### Configuration

All settings are `FT_`-prefixed environment variables in `.env`; every one is documented in
[.env.example](.env.example) and defined in `app/config.py`.

### Running without Docker (development)

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,volatility]"
pytest -q
mkdir -p data symbols
FT_EVIDENCE_DIR=./evidence FT_DATA_DIR=./data FT_SYMBOLS_DIR=./symbols \
  uvicorn app.main:create_app --factory --reload
```

Team workflow, branch rules and guidance for AI coding assistants:
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md). Outstanding setup and hand-off work: [TODO.md](TODO.md).

## Features

> **Stub — to be completed by the team.** Infrastructure exists for each item below; the forensic
> content is still being written. Update each entry's status and description as it lands.

### Evidence handling
- **Status:** infrastructure done
- Scan the read-only evidence folder, SHA-256 hashing, per-image description and notes.
- _TODO: describe OS detection and what is shown per image._

### Volatility plugins
- **Status:** TODO
- _TODO: list the supported plugins, what each is used for, and their allowed arguments._

| Plugin | Purpose | Arguments | Auto-enumerate |
|---|---|---|---|
| _e.g. `windows.pslist.PsList`_ | _TODO_ | _TODO_ | _TODO_ |

### Preset queries
- **Status:** TODO
- _TODO: describe the hardcoded suggested queries and when to use them._

### Auto-enumeration
- **Status:** infrastructure done, plugin set TODO
- _TODO: list what runs when "Auto-enumerate" is clicked and why._

### Results browsing
- **Status:** infrastructure done
- Paged, filterable results tables; tree output (e.g. process trees) is indented; each row has a
  citation key `R<run>:<row>`.
- _TODO: describe any per-plugin views or highlighting._

### AI analysis
- **Status:** infrastructure done, prompts TODO
- Ask questions, summarise a run, cited claims with clickable row links, provenance dropdown,
  validated one-click query suggestions.
- _TODO: describe the analysis approach, what context is sent, and known limitations._

### Notes and export
- **Status:** notes done, export TODO
- _TODO: describe the markdown export once implemented._

## Limitations

- Single user, localhost only, no authentication — do not expose the port to a network.
- Windows memory images only for now (Linux/macOS need custom symbol tables).
- Data sent to the AI provider includes evidence-derived strings; only use a provider you are
  permitted to share case data with.
