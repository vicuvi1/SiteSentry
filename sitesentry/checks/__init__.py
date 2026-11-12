"""Individual security checks. Each module exposes pure functions that take
already-collected data (headers, responses...) and return Finding objects, so
they can be unit-tested without any network access."""
