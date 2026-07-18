# Publishing checklist

This source tree is prepared for a public GitHub repository, not for an unaudited production deployment.

## Before the first push

1. Confirm that the final `queryattest` repository/package name is available and complete an appropriate trademark review before public launch.
2. Review every claim in `README.md`, `docs/evidence-model.md`, and `docs/implementation-status.md`.
3. Replace sample maintainership/contact wording where appropriate.
4. After creating the GitHub repository, add its final Homepage, Repository, Issues, and Changelog URLs to `pyproject.toml` before publishing to PyPI.
5. Confirm that `uv.lock` contains only public PyPI and `files.pythonhosted.org` URLs.
6. Run the deterministic gates:

   ```bash
   uv sync --frozen --extra dev
   make check
   ```

7. Run network/live-system gates:

   ```bash
   make dependency-audit
   docker compose up -d postgres
   export TEST_DATABASE_URL='postgresql://queryattest_reader:queryattest_reader@127.0.0.1:5432/queryattest'
   make integration
   ```

8. Review `git status --ignored` and ensure no `.env`, `.queryattest/`, database file, cache, coverage output, or `dist/` artifact is staged.
9. Enable GitHub private vulnerability reporting and branch protection after creating the repository.
10. Require the `quality` workflow before merging to the default branch.

## Suggested GitHub metadata

- Repository name: `queryattest`
- Description: `Evidence-backed database execution for AI agents over MCP.`
- Topics: `mcp`, `postgresql`, `ai-agents`, `attestation`, `data-governance`, `sql-security`, `rls`, `text-to-sql`
- First release tag: `v0.1.1-alpha`

Keep the repository description narrow: QueryAttest attests authorized, bounded execution and configured checks. It does not claim to prove that an LLM selected the correct metric from natural language.

## Suggested first commit

```bash
git init
git add .
git commit -m "Initial public alpha release"
git branch -M main
git remote add origin <repository-url>
git push -u origin main
```

## Suggested repository settings

- Enable private vulnerability reporting and Dependabot alerts.
- Protect `main`; require pull requests and all CI jobs.
- Prevent force pushes and branch deletion.
- Enable secret scanning where available.
- Create a `v0.1.1-alpha` release only after CI passes from the public repository.
- Do not publish `server.json` to the MCP Registry until the final repository/package URL and remote-authentication posture are known.
