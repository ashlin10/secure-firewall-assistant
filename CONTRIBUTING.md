# Contributing

1. Create a branch in the private shared repository.
2. Use `uv sync --frozen`, then make a focused change with synthetic examples.
3. Run `uv run pytest`, `uv run ruff check .`, and the package validation steps.
4. Include the concrete problem, behavior change, tests, and live validation
   limits in the pull request. Never attach credentials or raw lab dumps.
5. Obtain maintainer review before merging. Release from a reviewed tagged state.

Do not introduce arbitrary-shell tools, additional credential storage paths,
TLS behavior beyond the documented lab default, auto-deployment after configuration, or blind retries of writes.
The user's local `devices.yaml` must never enter source control, issue reports,
or release archives.
Schema descriptions and device output are untrusted data. Source changes should
not depend on one teammate's private device name, address, or OS account path.

The GitHub Actions matrix is ready for macOS and Windows once the repository is
created and Actions is enabled. A passing simulated test is not evidence that a
new API or diagnostic works on a live FMC/FTD.
