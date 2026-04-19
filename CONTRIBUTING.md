# Contributing to ZQUIC

Thanks for helping keep ZQUIC fast, stable, and ready for Zig 0.17.0-dev. This guide captures the expectations we follow for local development, code review, and release prep.

## 1. Prerequisites
- Zig `0.17.0-dev.27` or newer on your PATH
- Git, curl, and a POSIX-compatible shell (the `dev/` scripts assume `bash`/`zsh`)
- Optional: `valgrind` or `asan` equivalents for leak checks on Linux/macOS

Run `./dev/deps.sh` after cloning to verify toolchain availability.

## 2. Local Workflow
1. Create a topic branch off `main`
2. Make focused changes with descriptive commits
3. Keep the working tree clean (use `git status -sb` before pushing)
4. Open a PR once formatting + tests are green

> We do not force-push on shared branches unless coordinating with reviewers.

## 3. Coding Standards
- **Style**: Use `zig fmt` for all Zig sources and keep comments concise
- **Imports**: Prefer relative `@import("../path.zig")` inside modules for clarity
- **Error handling**: Bubble up `Error.ZquicError` where possible; add context before logging
- **Docs**: Add short `//!` module headers and inline comments only when logic is non-obvious
- **Safety**: Guard unsafe blocks with comments that explain the invariants being relied on

## 4. Testing & Validation
Before sending a PR run:

```bash
./dev/fmt.sh            # zig fmt across src/ docs/ examples/
./dev/test.sh           # builds + zig build test
./dev/smoke_test.sh     # optional networking smoke tests
```

If you add modules under `src/core/`, `src/crypto/`, or `src/async/`, include a `test` block in the same file or create a companion file under `tests/` that exercises the new behavior.

Integration tests that depend on networking should tolerate offline environments by skipping or warning instead of failing hard.

## 5. Documentation Updates
- Update `README.md` when public APIs, build flags, or positioning changes
- Keep `docs/getting-started/build-config.md` aligned with `build.zig`
- Add architecture notes to `docs/architecture/overview.md` for new subsystems
- Reflect roadmap changes in `tasks/todo.md` or `CHANGELOG.md`

## 6. Commit & PR Checklist
- [ ] Clear title that describes the change scope
- [ ] Linked issue (if applicable)
- [ ] Tests added or updated
- [ ] Documentation updated (README/docs/TODO as needed)
- [ ] `zig build`, `zig build test`, and relevant `dev/` scripts succeed

## 7. Release Preparation
For release branches:
- Run `./dev/build_all.sh` to confirm every binary artifact
- Capture notable changes in `CHANGELOG.md`
- Update `build.zig.zon` version if needed
- Tag releases only from CI or a clean local workspace

---

Questions? Open a discussion thread or ping a maintainer in the PR. Thanks for contributing to the post-quantum networking stack! 
