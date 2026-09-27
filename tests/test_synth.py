"""Test synthetic data generator determinism and defect injection."""

import json
import tempfile

from satsa.synth.generator import SyntheticDataGenerator


def test_generator_determinism():
    gen1 = SyntheticDataGenerator(seed=42, base_alerts_per_entity=100)
    data1, gt1 = gen1.generate()

    gen2 = SyntheticDataGenerator(seed=42, base_alerts_per_entity=100)
    data2, gt2 = gen2.generate()

    assert len(data1["alert"]) == len(data2["alert"])
    assert data1["alert"][0].alert_id == data2["alert"][0].alert_id
    assert gt1.defects[0].entity_id == gt2.defects[0].entity_id


def test_generator_save_dataset():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = SyntheticDataGenerator(seed=42, base_alerts_per_entity=50)
        csv_dir, gt_path = gen.save_dataset(tmpdir)

        assert (csv_dir / "alert.csv").exists()
        assert (csv_dir / "entity.csv").exists()
        assert gt_path.exists()

        with open(gt_path, encoding="utf-8") as f:
            gt_data = json.load(f)
            assert "CSE-01" in gt_data["clean_entities"]
            assert len(gt_data["defects"]) >= 8
