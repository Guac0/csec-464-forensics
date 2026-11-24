# evidence/

Put RAM images to analyze here (e.g. `.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`).

- This folder is mounted **read-only** into the container at `/evidence`
  (`./evidence:/evidence:ro` in `docker-compose.yml`). Neither the app nor volatility3 can
  modify, delete or add files here, so evidence hashes stay valid.
- Everything in this folder except this README is **git-ignored**. Never commit memory images
  (they are large and may contain sensitive data: credentials, personal data, keys).
  A pre-commit hook also rejects common memory-image extensions anywhere in the repo.
- Subfolders are fine; the app scans recursively.
- On Windows + Docker Desktop, keep the repository (and this folder) inside the WSL2 filesystem
  (e.g. `\\wsl$\Ubuntu\home\<you>\forensics`) - bind mounts from `C:\` are very slow for
  multi-GB files.
- Record where each image came from (source, acquisition tool, SHA-256) in your case notes.
