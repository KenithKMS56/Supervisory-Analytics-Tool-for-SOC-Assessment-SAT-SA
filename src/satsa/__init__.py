"""SAT-SA: Supervisory Analytics Tool for SOC Assessment."""

__version__ = "0.1.0"

# What every SAT-SA output is, and is not. Shown wherever findings are shown: every page
# of the web app, every page of every PDF, the HTML reports, and as a field / column in the
# JSON and CSV exports. tests/test_supervisory_notice.py checks each of those places.
SUPERVISORY_NOTICE = "Indicators requiring supervisory review; not a compliance determination."
# The same statement for a single finding.
FINDING_NOTICE = "Indicator requiring supervisory review; not a compliance determination."
