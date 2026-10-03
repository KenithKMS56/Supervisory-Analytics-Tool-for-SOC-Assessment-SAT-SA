"""SAT-SA: Supervisory Analytics Tool for SOC Assessment."""

import os

# Polars allocates with mimalloc on Windows, which by default holds freed memory for a while
# before returning it to the system. Ingest frees large frames in quick succession, and the held
# memory raised its peak. Returning it at once, together with reading the largest CSV first
# (ingest/pipeline.py), took the peak at 5,000,000 alerts from 5,761 to 5,435 MiB
# (docs/benchmarks.md, "Peak-memory change"). mimalloc reads this when Polars is first imported,
# so it is set here, before any SAT-SA module imports Polars; a setting in the environment wins.
# Polars builds for other platforms do not use mimalloc and ignore it.
os.environ.setdefault("MIMALLOC_PURGE_DELAY", "0")

__version__ = "0.1.0"

# What every SAT-SA output is, and is not. Shown wherever findings are shown: every page
# of the web app, every page of every PDF, the HTML reports, and as a field / column in the
# JSON and CSV exports. tests/test_supervisory_notice.py checks each of those places.
SUPERVISORY_NOTICE = "Indicators requiring supervisory review; not a compliance determination."
# The same statement for a single finding.
FINDING_NOTICE = "Indicator requiring supervisory review; not a compliance determination."
