"""Runtime settings. Read once per app instance; never log secrets."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database_url: str
    model_path: Path
    api_key: str
    max_batch: int = 250
    risk_threshold: float = 0.0

    @classmethod
    def from_env(cls) -> Settings:
        key = os.getenv("NETWORKPULSE_API_KEY", "")
        if len(key) < 16:
            raise ValueError("NETWORKPULSE_API_KEY must contain at least 16 characters")
        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///./data/networkpulse.db"),
            model_path=Path(os.getenv("MODEL_PATH", "data/model.joblib")),
            api_key=key,
            max_batch=int(os.getenv("MAX_BATCH", "250")),
        )
