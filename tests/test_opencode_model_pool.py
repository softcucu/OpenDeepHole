import asyncio
from types import SimpleNamespace

from backend.opencode.model_pool import acquire_model_lease, model_options, release_model_lease


def test_model_options_falls_back_to_default_model() -> None:
    cfg = SimpleNamespace(tool="opencode", executable="opencode", model="default-model", models=[])

    options = model_options(cfg, global_concurrency=3)

    assert len(options) == 1
    assert options[0].id == "default"
    assert options[0].model == "default-model"
    assert options[0].max_concurrency == 3


def test_model_options_normalizes_enabled_models() -> None:
    cfg = SimpleNamespace(
        models=[
            {
                "id": "fast",
                "model": "fast-model",
                "capability": "low",
                "weight": 2,
                "max_concurrency": 2,
            },
            {"id": "off", "model": "off-model", "enabled": False},
        ],
    )

    options = model_options(cfg, global_concurrency=4)

    assert [option.id for option in options] == ["fast"]
    assert options[0].capability == "low"
    assert options[0].weight == 2
    assert options[0].max_concurrency == 2


def test_acquire_model_lease_filters_by_capability_and_releases() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 3, "max_concurrency": 2},
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 1},
            ],
        )

        lease = await acquire_model_lease(cfg, global_concurrency=2, required_capability="high")
        try:
            assert lease is not None
            assert lease.option.id == "deep"
            assert lease.running == 1
            assert lease.global_running == 1
        finally:
            await release_model_lease(lease)

    asyncio.run(run())


def test_acquire_model_lease_prefers_weighted_fast_model_for_any_capability() -> None:
    async def run():
        cfg = SimpleNamespace(
            models=[
                {"id": "fast", "model": "fast-model", "capability": "low", "weight": 3, "max_concurrency": 3},
                {"id": "deep", "model": "deep-model", "capability": "high", "weight": 1, "max_concurrency": 3},
            ],
        )

        first = await acquire_model_lease(cfg, global_concurrency=3, required_capability="any")
        second = await acquire_model_lease(cfg, global_concurrency=3, required_capability="any")
        try:
            assert first is not None
            assert second is not None
            assert first.option.id == "fast"
            assert second.option.id == "deep"
        finally:
            await release_model_lease(second)
            await release_model_lease(first)

    asyncio.run(run())
