# Testing

From the repository root, run these commands with Python 3.11 or later.

```sh
python -B -m unittest discover -s tests -v
python -B ci_checks.py
```

Tests cover the two independent budgets, the grammar and file-size ceilings, whitespace accounting, duplicate ordering and case, raw octet ranges, percent escapes, invalid paths, descriptor validation and quiet broken stdout handling. The FIFO test uses a real FIFO when `os.mkfifo` is available. Otherwise it supplies FIFO metadata and verifies rejection before open. CI runs on Ubuntu and Windows.

The four synthetic examples exercise exits 0, 1 and 2. The checker verifies the complete JSON reports, their exit codes and empty stderr. Example files preserve their exact bytes across Git checkouts, including the invalid fixture's trailing line feed.
