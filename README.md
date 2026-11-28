# Forensics Tool: AI-assisted memory forensics (proof of concept)

A web app for analysing Windows memory images with
[volatility3](https://github.com/volatilityfoundation/volatility3), with an external AI model
that helps interpret the output and suggests what to run next.

## Why

Volatility is powerful but hard to drive from the command line: plugin names and options are easy
to get wrong, the output is large, and it's hard to keep track of what was run and what it showed.
This app wraps it in a local web page that guides the analyst, keeps every result with its exact
command and hashes, and adds an AI assistant that has to cite the rows behind every claim.

**AI output is a lead, never evidence.** It is always shown apart from tool output and must be
checked against the rows it cites.

This is a small proof of concept: **one user, on your own computer, reachable only from that
computer (`127.0.0.1`), no login.**

## Running it

**Requirements:** Docker Desktop (Windows/macOS) or Docker Engine with Compose v2.24+ (Linux), and
an OpenAI-compatible AI endpoint (e.g. a local Ollama/vLLM server or an approved hosted provider).

1. **Configure** (optional but needed for AI features):

   ```bash
   cp .env.example .env
   # edit FT_AI_BASE_URL, FT_AI_API_KEY, FT_AI_MODEL
   ```

2. **Add evidence:** copy memory images into the `evidence/` folder. The app can only read it,
   and git ignores it (images are too big for git).

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
mkdir -p data symbols backups
FT_EVIDENCE_DIR=./evidence FT_DATA_DIR=./data FT_SYMBOLS_DIR=./symbols FT_BACKUP_DIR=./backups \
  uvicorn app.main:create_app --factory --reload
```

More on development (tests, branches, migrations): [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## What you can do

- **Run volatility plugins from a form** instead of the command line. Only plugins and options
  the forensics team has allowed can run, and every run keeps its exact command, tool version,
  image hash and raw output.
- **Browse results** in searchable, filterable tables and export them as CSV.
- **Follow the recommended next steps:** a checklist of what to run next, based on what has run
  so far.
- **See automatic flags and findings** from small checks (hooks) that run after each plugin.
- **Ask an AI** about the results. Every claim cites the rows it relies on, and the app checks
  those citations. The AI can also suggest runs, or work towards a goal you give it, asking
  your approval before each run.
- **Group images into cases** (before/after snapshots, several machines), share findings
  between them, watch for indicators across all of them and compare two images.
- **Keep a trail:** notes with full history, a tamper-evident activity log, reports and ZIP
  exports with hashes, automatic backups.

The [user guide](docs/USER_GUIDE.md) explains each feature. The **Content** page in the app
shows which plugins are available right now.

## Where to go next

| You want to... | Read |
|---|---|
| Use the tool to examine an image | [docs/USER_GUIDE.md](docs/USER_GUIDE.md) |
| Add or change plugins, recommendations, hooks or AI prompts (forensics team) | [forensics/README.md](forensics/README.md) |
| Work on the app itself: setup, tests, branches, migrations | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| Test how well the AI answers | [evals/README.md](evals/README.md) |
| See what is still open | [TODO.md](TODO.md) |
| Brief an AI coding assistant | [AGENTS.md](AGENTS.md) (it reads this itself) |

## Limitations

- One user, no login. The app only listens on `127.0.0.1`: don't expose it to a network.
- Windows memory images only (Linux and macOS images need custom symbol files).
- Data sent to the AI provider includes text from the evidence. Only use a provider you are
  allowed to share case data with.
