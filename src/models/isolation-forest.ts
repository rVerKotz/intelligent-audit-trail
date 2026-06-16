/* ./src/models/isolation-forest.ts */
// @ts-ignore
import { IsolationForest } from 'isolation-forest';

/**
 * Converts raw {@link AuditLogMetadata}-shaped records into fixed-length
 * numerical vectors suitable for the Isolation Forest algorithm.
 *
 * **Feature vector layout** (`length = 7`):
 * ```
 * [hour, actionVal, resourceVal, log2Duration × 4]
 * ```
 *
 * | Index | Feature               | Notes                                        |
 * |-------|-----------------------|----------------------------------------------|
 * | 0     | Hour of day (0–23)    | Detects after-hours anomalies                |
 * | 1     | Action type (1–4)     | CREATE=1, READ=2, UPDATE=3, DELETE=4         |
 * | 2     | Resource index (≥1)   | Auto-indexed; stable within a model instance |
 * | 3–6   | log₂(duration + 1)   | Duplicated ×4 to prevent categorical swamping|
 */
export class AuditDataTransformer {
  private resourceMap: Map<string, number> = new Map();

  /**
   * Maps CRUD action strings to their ordinal representation.
   * Unknown actions fall back to `0`.
   */
  private readonly actionMap: Record<string, number> = {
    CREATE: 1,
    READ:   2,
    UPDATE: 3,
    DELETE: 4,
  };

  /**
   * Transforms a single log entry into a numerical feature vector.
   *
   * Logarithmic duration scaling (`Math.log2`) compresses the mathematical
   * space so that extreme outliers (e.g. 50 000 ms) do not push moderate
   * anomalies (e.g. 15 000 ms) into the "normal" cluster.
   *
   * @param resource  - Logical resource name (e.g. `'Article'`).
   * @param action    - CRUD operation string.
   * @param duration  - Wall-clock duration of the operation in milliseconds.
   * @param timestamp - ISO-8601 timestamp used to extract the hour component.
   * @returns A 7-element numerical array for the Isolation Forest model.
   */
  transform(
    resource: string,
    action: string,
    duration: number,
    timestamp: string,
  ): number[] {
    const hour      = new Date(timestamp).getHours();
    const actionVal = this.actionMap[action] ?? 0;

    if (!this.resourceMap.has(resource)) {
      this.resourceMap.set(resource, this.resourceMap.size + 1);
    }
    const resourceVal     = this.resourceMap.get(resource) ?? 0;
    const scaledDuration  = Math.log2(duration + 1);

    return [hour, actionVal, resourceVal,
            scaledDuration, scaledDuration, scaledDuration, scaledDuration];
  }
}

/**
 * Per-`resource:action` statistics collected from the TRAINING baseline.
 *
 * Used purely for **explainability** — turning a raw anomaly score into a
 * human-readable {@link AuditMessageDetail} (e.g. "duration 16200ms > p99
 * threshold 2150ms for Analyze/CREATE. Hour 14 is unusual; typical hours are
 * 9-13, 15-17.").
 *
 * @internal
 */
interface DurationProfile {
  /** All observed durations (ms) for this resource/action pair. */
  durations: number[];
  /** Frequency map of hour-of-day (0-23) → number of observations. */
  hourCounts: Map<number, number>;
}

/**
 * Computes the linear-interpolation percentile of a numeric array.
 *
 * @param values     - Unsorted array of numeric samples.
 * @param percentile - Desired percentile in `[0, 1]` (e.g. `0.99` for p99).
 * @returns The interpolated percentile value, or `0` for an empty array.
 *
 * @internal
 */
function percentile(values: number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = (sorted.length - 1) * percentile;
  const lower = Math.floor(idx);
  const upper = Math.ceil(idx);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (idx - lower);
}

/**
 * Wraps an Isolation Forest model with a Supabase-aware training pipeline.
 *
 * **Training strategy — Cloned Synthetic Outliers:**
 * Real baseline events are cloned with extreme durations (3×–10× the observed
 * maximum) so the model learns that high latency is anomalous even when the
 * resource and action type are entirely normal.
 *
 * **Threshold calibration:**
 * The anomaly threshold is set at the 98th percentile of baseline scores plus
 * a small margin (`+0.015`). This means roughly 2 % of normal events will be
 * flagged — a deliberate trade-off that keeps false-positive rates low while
 * still catching genuine outliers.
 *
 * **Explainability:**
 * Alongside the raw model, a lightweight per-`resource:action` duration/hour
 * profile is retained from the baseline (see {@link getDurationStats}) so
 * that {@link IntelligentAuditTrail} can build a human-readable `reason` for
 * any flagged event without re-querying the database.
 */
export class AuditAnomalyDetector {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private model: any;
  private transformer: AuditDataTransformer;
  private isTrained = false;

  /**
   * Auto-calibrated anomaly threshold.
   * Initialised conservatively at `0.60`; overwritten by {@link loadPresetBaseline}.
   */
  private dynamicThreshold = 0.60;

  /**
   * Per-`resource:action` duration & hour-of-day profiles built from the
   * TRAINING baseline. Synthetic outliers are intentionally **excluded** so
   * that `p99` reflects genuinely-observed traffic, not injected extremes.
   *
   * @internal
   */
  private durationProfiles: Map<string, DurationProfile> = new Map();

  constructor() {
    this.model       = new IsolationForest(100);
    this.transformer = new AuditDataTransformer();
  }

  /**
   * The current anomaly decision threshold used by {@link analyzeActivity}.
   *
   * Exposed so that {@link IntelligentAuditTrail} can compute granular severity
   * bands (WARN / ERROR / FATAL / CRITICAL) without duplicating logic.
   *
   * @returns A score in the range `[0, 1]` above which an event is flagged.
   */
  get threshold(): number {
    return this.dynamicThreshold;
  }

  /**
   * Builds the `resource:action` key used to index {@link durationProfiles}.
   * @internal
   */
  private profileKey(resource: string, action: string): string {
    return `${resource}:${action}`;
  }

  /**
   * Trains the Isolation Forest on recorded normal-behaviour samples and
   * auto-calibrates the anomaly threshold to the 98th percentile of those scores.
   *
   * **Synthetic outlier injection:**
   * 10 % of the baseline length (minimum 10) are generated by cloning real
   * events with artificially extreme durations. This teaches the model that
   * slow operations are anomalous even when every other feature is normal.
   *
   * **Duration/hour profiling:**
   * Every *real* baseline record (excluding synthetic outliers) is also
   * folded into {@link durationProfiles}, keyed by `resource:action`, to
   * power {@link getDurationStats}.
   *
   * @param rawBaseline - Array of previously recorded {@link AuditLogMetadata}
   *   entries collected during TRAINING mode.
   */
  loadPresetBaseline(
    rawBaseline: Array<{ resource: string; action: string; duration: number; timestamp: string }>,
  ): void {
    const trainingData = rawBaseline.map(item =>
      this.transformer.transform(item.resource, item.action, item.duration, item.timestamp),
    );

    // ── Build per-resource/action duration & hour profiles ──────────────────
    this.durationProfiles.clear();
    for (const item of rawBaseline) {
      const key = this.profileKey(item.resource, item.action);
      let profile = this.durationProfiles.get(key);
      if (!profile) {
        profile = { durations: [], hourCounts: new Map() };
        this.durationProfiles.set(key, profile);
      }
      profile.durations.push(item.duration);

      const hour = new Date(item.timestamp).getHours();
      profile.hourCounts.set(hour, (profile.hourCounts.get(hour) ?? 0) + 1);
    }

    const maxNormalDuration = Math.max(...rawBaseline.map(b => b.duration));
    const syntheticOutliers: number[][] = [];
    const outlierCount = Math.max(10, Math.floor(rawBaseline.length * 0.10));

    for (let i = 0; i < outlierCount; i++) {
      const base            = rawBaseline[Math.floor(Math.random() * rawBaseline.length)];
      const extremeDuration = maxNormalDuration * (3 + Math.random() * 7);
      syntheticOutliers.push(
        this.transformer.transform(base.resource, base.action, extremeDuration, base.timestamp),
      );
    }

    this.model.fit([...trainingData, ...syntheticOutliers]);
    this.isTrained = true;

    const sortedScores = ([...this.model.scores(trainingData)] as number[]).sort((a, b) => a - b);
    const p98Index      = Math.floor(sortedScores.length * 0.98);
    const robustMax     = sortedScores[p98Index];
    this.dynamicThreshold = robustMax + 0.015;

    console.log(
      `[ML Engine]: Baseline loaded with ${trainingData.length} normal samples ` +
      `(+${outlierCount} synthetic boundaries).`,
    );
    console.log(
      `[ML Engine]: Auto-calibrated threshold → ${this.dynamicThreshold.toFixed(4)} ` +
      `(98th pct: ${robustMax.toFixed(4)} | abs max: ${sortedScores[sortedScores.length - 1].toFixed(4)})`,
    );
  }

  /**
   * Returns the baseline duration/hour profile for a given `resource`/`action`
   * pair, used to build the explainable `reason` shown on anomalous events.
   *
   * @param resource - Logical resource identifier (e.g. `'Article'`).
   * @param action   - CRUD operation string.
   * @returns An object containing:
   * - `p99` — the 99th-percentile baseline duration in ms (`0` if no samples).
   * - `sampleCount` — number of baseline samples backing this profile.
   * - `typicalHours` — sorted list of hours-of-day (0-23) that appeared at
   *   least twice in the baseline for this resource/action, capped to the
   *   8 most frequent hours. Empty if no baseline data exists.
   *
   * @example
   * ```ts
   * const { p99, typicalHours } = detector.getDurationStats('Analyze', 'CREATE');
   * // p99 -> 2150, typicalHours -> [9, 10, 11, 12, 13, 15, 16]
   * ```
   */
  getDurationStats(resource: string, action: string): {
    p99: number;
    sampleCount: number;
    typicalHours: number[];
  } {
    const profile = this.durationProfiles.get(this.profileKey(resource, action));
    if (!profile || profile.durations.length === 0) {
      return { p99: 0, sampleCount: 0, typicalHours: [] };
    }

    const typicalHours = [...profile.hourCounts.entries()]
      .filter(([, count]) => count >= 2 || profile.durations.length < 4)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([hour]) => hour)
      .sort((a, b) => a - b);

    return {
      p99: Math.round(percentile(profile.durations, 0.99)),
      sampleCount: profile.durations.length,
      typicalHours,
    };
  }

  /**
   * Scores a single activity vector against the trained Isolation Forest.
   *
   * @param resource - Logical resource identifier (e.g. `'Article'`).
   * @param action   - CRUD operation string.
   * @param duration - Wall-clock duration of the operation in milliseconds.
   * @returns An object containing the raw anomaly `score` and a boolean
   *   `isSuspicious` flag (`true` when `score > threshold`).
   * @throws {Error} If called before {@link loadPresetBaseline} has been invoked.
   */
  analyzeActivity(
    resource: string,
    action: string,
    duration: number,
  ): { score: number; isSuspicious: boolean } {
    if (!this.isTrained) {
      throw new Error('AuditAnomalyDetector: model must be trained before calling analyzeActivity().');
    }
    const vector = this.transformer.transform(resource, action, duration, new Date().toISOString());
    const score  = (this.model.scores([vector]) as number[])[0];
    return { score, isSuspicious: score > this.dynamicThreshold };
  }
}