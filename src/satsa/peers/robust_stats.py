"""Robust statistics module: median, MAD, robust z-score, IQR, and percentile rank."""

from collections.abc import Sequence


class RobustStats:
    """Deterministic, robust statistical estimators resistant to outliers."""

    @staticmethod
    def median(values: Sequence[float]) -> float:
        """Compute median of sequence."""
        if not values:
            return 0.0
        s = sorted(values)
        n = len(s)
        mid = n // 2
        return (s[mid - 1] + s[mid]) / 2.0 if n % 2 == 0 else float(s[mid])

    @staticmethod
    def mad(values: Sequence[float]) -> float:
        """Median Absolute Deviation (MAD): median(|x - median(x)|)."""
        if not values:
            return 0.0
        med = RobustStats.median(values)
        devs = [abs(x - med) for x in values]
        return RobustStats.median(devs)

    @staticmethod
    def robust_z_score(
        value: float,
        values: Sequence[float] | None = None,
        median: float | None = None,
        mad: float | None = None,
    ) -> float:
        """
        Calculate robust z-score: 0.6745 * (x - median) / MAD.
        Handles zero MAD via fallback to mean absolute deviation or zero.
        """
        if median is None and values is not None:
            median = RobustStats.median(values)
        if mad is None and values is not None:
            mad = RobustStats.mad(values)

        med = median or 0.0
        m = mad or 0.0

        if m == 0.0:
            # Fallback: if value matches median, z=0; otherwise small non-zero denominator
            if values:
                mean_dev = sum(abs(x - med) for x in values) / len(values)
                if mean_dev > 0:
                    return float(0.6745 * (value - med) / (1.2533 * mean_dev))
            return 0.0

        return float(0.6745 * (value - med) / m)

    @staticmethod
    def percentile(values: Sequence[float], p: float) -> float:
        """Percentile (p in 0..100) using linear interpolation."""
        if not values:
            return 0.0
        s = sorted(values)
        if len(s) == 1:
            return float(s[0])
        k = (len(s) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1
        if c >= len(s):
            return float(s[-1])
        d0 = s[f] * (c - k)
        d1 = s[c] * (k - f)
        return float(d0 + d1)

    @staticmethod
    def percentile_rank(value: float, values: Sequence[float]) -> float:
        """Compute percentile rank (0..100) of value in values."""
        if not values:
            return 50.0
        count_less = sum(1 for x in values if x < value)
        count_equal = sum(1 for x in values if x == value)
        return float(100.0 * (count_less + 0.5 * count_equal) / len(values))

    @staticmethod
    def iqr_bounds(values: Sequence[float]) -> tuple[float, float, float, float]:
        """Return (p25, p50, p75, iqr)."""
        p25 = RobustStats.percentile(values, 25.0)
        p50 = RobustStats.percentile(values, 50.0)
        p75 = RobustStats.percentile(values, 75.0)
        return p25, p50, p75, p75 - p25
