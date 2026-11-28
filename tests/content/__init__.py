"""Frozen copy of forensics content used by infrastructure tests (tests/conftest.py switches to
it with ``content.use_root("tests.content")``), so the forensics team can change forensics/
without breaking infrastructure tests. Only tests/test_forensics_content.py loads forensics/.
Change this copy only when an infrastructure test needs different content."""
