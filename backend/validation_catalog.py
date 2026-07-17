"""Server-side catalog of deployable product validation targets."""

from __future__ import annotations

from pathlib import Path

from agent.vulnerability_validation import PRODUCT_VALIDATORS_DIR, discover_validator_manifests
from backend.logger import get_logger
from backend.models import ValidationTarget


logger = get_logger(__name__)
_catalog: tuple[ValidationTarget, ...] | None = None


def refresh_validation_catalog(
    validators_dir: Path = PRODUCT_VALIDATORS_DIR,
) -> list[ValidationTarget]:
    global _catalog
    manifests, errors = discover_validator_manifests(validators_dir)
    for error in errors:
        logger.error("Invalid product validator excluded from catalog: %s", error)
    _catalog = tuple(
        ValidationTarget(
            validator_id=item.validator_id,
            product=item.product,
            validation_environment=item.validation_environment,
            timeout_seconds=item.timeout_seconds,
        )
        for item in manifests
    )
    logger.info("Loaded %d product validation target(s)", len(_catalog))
    return list(_catalog)


def get_validation_catalog() -> list[ValidationTarget]:
    if _catalog is None:
        return refresh_validation_catalog()
    return list(_catalog)


def find_validation_target(product: str, validation_environment: str) -> ValidationTarget | None:
    key = (str(product or "").strip(), str(validation_environment or "").strip())
    return next(
        (
            item
            for item in get_validation_catalog()
            if (item.product, item.validation_environment) == key
        ),
        None,
    )
