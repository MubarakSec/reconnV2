from __future__ import annotations

import json
from typing import List

from recon_cli import config
from recon_cli.pipeline.context import PipelineContext
from recon_cli.pipeline.feature_defs import FEATURE_KEYS
from recon_cli.pipeline.stage_base import Stage

try:
    from recon_cli.learning.collector import DatasetStore, HostFeatures
    from recon_cli.learning.model import LearningModel
except ImportError:  # pragma: no cover - optional dependency
    DatasetStore = None  # type: ignore
    HostFeatures = None  # type: ignore
    LearningModel = None  # type: ignore


class LearningStage(Stage):
    name = "learning"

    def is_enabled(self, context: PipelineContext) -> bool:
        return bool(getattr(context.runtime_config, "enable_learning", False))

    def execute(self, context: PipelineContext) -> None:
        features_path = context.record.paths.artifact("correlation/features.json")
        if not features_path.exists():
            context.logger.info("No correlation features found; skipping learning stage")
            return
        try:
            features_payload = json.loads(features_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            context.logger.warning("Invalid features artifact; skipping learning stage")
            return
        if not isinstance(features_payload, dict):
            context.logger.warning("Unexpected features format; skipping learning stage")
            return

        if DatasetStore is None or HostFeatures is None or LearningModel is None:
            context.logger.warning("Learning dependencies unavailable; skipping learning stage")
            return

        learning_root = config.RECON_HOME / "learning"
        store = DatasetStore(learning_root)
        job_id = context.record.spec.job_id
        host_features: List[HostFeatures] = []
        records = []
        for host, feats in features_payload.items():
            feature_vector = {key: float(feats.get(key, 0.0)) for key in FEATURE_KEYS}
            host_feature = HostFeatures(host=host, features=feature_vector)
            host_features.append(host_feature)
            records.append(host_feature.to_record(job_id))
        if not records:
            context.logger.info("No host features available for learning stage")
            return

        store.append(records)
        labeled = store.load_labeled()
        try:
            model = LearningModel(learning_root, FEATURE_KEYS)
            trained = model.train(labeled) if labeled else False
            predictions = model.predict(host_features)
        except Exception as exc:  # pragma: no cover - optional dependency
            context.logger.warning("Learning model unavailable; skipping learning stage: %s", exc)
            return

        artifacts_dir = context.record.paths.ensure_subdir("learning")
        predictions_path = artifacts_dir / "predictions.json"
        if predictions:
            predictions_path.write_text(json.dumps(predictions, indent=2, sort_keys=True), encoding="utf-8")
            for host, probability in sorted(predictions.items(), key=lambda item: item[1], reverse=True):
                context.results.append(
                    {
                        "type": "learning_prediction",
                        "source": "learning",
                        "hostname": host,
                        "probability": probability,
                    }
                )
        stats = context.record.metadata.stats.setdefault("learning", {})
        stats.update(
            {
                "trained": bool(trained),
                "predictions": len(predictions),
            }
        )
        if predictions:
            stats["top_hosts"] = [
                [host, float(prob)]
                for host, prob in sorted(predictions.items(), key=lambda item: item[1], reverse=True)[:5]
            ]
        context.manager.update_metadata(context.record)
        context.logger.info(
            "Learning stage completed (trained=%s, predictions=%s)",
            trained,
            len(predictions),
        )
