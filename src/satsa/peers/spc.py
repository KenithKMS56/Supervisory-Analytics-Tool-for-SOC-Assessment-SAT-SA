"""Statistical Process Control (SPC): CUSUM and EWMA control charts.

A chart's centre and spread come only from an in-control reference period ("phase I") that
precedes the values it judges: the caller's `reference`, or else the first `PHASE_I` values of
the series. A baseline is never estimated from values that come later than the point being
tested, so adding a later month cannot change an earlier verdict.
"""

PHASE_I = 5

from collections.abc import Sequence

from satsa.peers.robust_stats import RobustStats


class SPCDetector:
    """Detects structural breaks and process shifts without machine learning."""

    @staticmethod
    def cusum(
        series: Sequence[float],
        slack_k: float = 0.5,
        threshold_h: float = 4.0,
        min_scale: float = 0.0,
        reference: Sequence[float] | None = None,
    ) -> tuple[list[float], list[float], list[int]]:
        """
        Two-sided tabular CUSUM control chart on standardized values.
        Returns (s_high, s_low, shift_indices).

        Without `reference` the centre and spread come from the first `PHASE_I` values of
        `series` (it needs at least that many). With `reference` (an in-control period that
        precedes the series) they come from those values. Either way every value of `series` is
        tested against a baseline fixed before it, so neither a later shift nor a later value
        is absorbed into the baseline.

        With `min_scale` > 0 each value is standardised as (x - median) / max(1.4826 * MAD,
        min_scale), so values that are nearly identical cannot turn a trivial difference
        into an infinite score. With the default 0 the scale is the MAD alone.
        """
        base = list(reference) if reference is not None else list(series[:PHASE_I])
        if not series or not base or (reference is None and len(series) < PHASE_I):
            return [], [], []

        med = RobustStats.median(base)
        mad = RobustStats.mad(base)
        s_high: list[float] = [0.0]
        s_low: list[float] = [0.0]
        alarms: list[int] = []

        for idx, val in enumerate(series):
            if min_scale > 0:
                z = (val - med) / max(1.4826 * mad, min_scale)
            else:
                z = RobustStats.robust_z_score(val, median=med, mad=mad)
            sh = max(0.0, s_high[-1] + z - slack_k)
            sl = max(0.0, s_low[-1] - z - slack_k)
            s_high.append(sh)
            s_low.append(sl)

            if sh > threshold_h or sl > threshold_h:
                alarms.append(idx)

        return s_high[1:], s_low[1:], alarms

    @staticmethod
    def ewma(
        series: Sequence[float],
        lambda_param: float = 0.2,
        l_sigma: float = 3.0,
        reference: Sequence[float] | None = None,
    ) -> tuple[list[float], list[tuple[float, float]], list[int]]:
        """
        EWMA control chart, centred on the in-control `reference` (default: the first `PHASE_I`
        values of `series`).
        Returns (ewma_values, control_limits (ucl, lcl), out_of_control_indices).
        """
        if len(series) < PHASE_I and reference is None:
            return [], [], []
        base = list(reference) if reference is not None else list(series[:PHASE_I])
        if not base:
            return [], [], []

        med = RobustStats.median(base)
        mad = RobustStats.mad(base)
        sigma = 1.4826 * mad if mad > 0 else 1.0

        z_prev = med
        ewma_vals: list[float] = []
        limits: list[tuple[float, float]] = []
        alarms: list[int] = []

        for t, x in enumerate(series, start=1):
            z_t = lambda_param * x + (1.0 - lambda_param) * z_prev
            ewma_vals.append(z_t)
            z_prev = z_t

            # Control limit factor
            factor = (lambda_param / (2.0 - lambda_param)) * (1.0 - (1.0 - lambda_param) ** (2 * t))
            half_width = l_sigma * sigma * (factor**0.5)
            ucl = med + half_width
            lcl = med - half_width
            limits.append((ucl, lcl))

            if z_t > ucl or z_t < lcl:
                alarms.append(t - 1)

        return ewma_vals, limits, alarms
