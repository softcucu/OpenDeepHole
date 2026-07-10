from datetime import datetime, timezone

from backend.opencode.output_format import with_local_timestamp


def test_with_local_timestamp_prefixes_every_line_and_is_idempotent() -> None:
    now = datetime(2026, 7, 10, 12, 34, 56, tzinfo=timezone.utc)
    original = "first\nsecond"

    formatted = with_local_timestamp(original, now=now)

    assert formatted == (
        "[2026-07-10 12:34:56] first\n"
        "[2026-07-10 12:34:56] second"
    )
    assert with_local_timestamp(formatted, now=now) == formatted


def test_with_local_timestamp_only_fills_missing_line_prefixes() -> None:
    now = datetime(2026, 7, 10, 12, 34, 56, tzinfo=timezone.utc)

    formatted = with_local_timestamp(
        "[2026-07-09 01:02:03] existing\nmissing",
        now=now,
    )

    assert formatted == (
        "[2026-07-09 01:02:03] existing\n"
        "[2026-07-10 12:34:56] missing"
    )


def test_with_local_timestamp_places_optional_prefix_after_existing_time() -> None:
    now = datetime(2026, 7, 10, 12, 34, 56, tzinfo=timezone.utc)
    original = "[2026-07-09 01:02:03] ready"

    formatted = with_local_timestamp(original, prefix="[model=test]", now=now)

    assert formatted == "[2026-07-09 01:02:03] [model=test] ready"
    assert with_local_timestamp(formatted, prefix="[model=test]", now=now) == formatted


def test_stage_prefix_is_inserted_between_existing_time_and_model() -> None:
    now = datetime(2026, 7, 10, 12, 34, 56, tzinfo=timezone.utc)
    model_line = "[2026-07-09 01:02:03] [model=test] running"

    formatted = with_local_timestamp(model_line, prefix="[threat]", now=now)

    assert formatted == "[2026-07-09 01:02:03] [threat] [model=test] running"
