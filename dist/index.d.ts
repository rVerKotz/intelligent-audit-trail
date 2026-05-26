/**
 * Metadata structure for audit logs.
 * Defines the schema for tracking resource access, actions, and anomaly detection results.
 *
 * @property resource     - The logical resource being accessed (e.g. `'Auth'`, `'Article'`).
 * @property functionName - The name of the Server Action that triggered the event.
 * @property action       - The CRUD operation type detected for this event.
 * @property userId       - Optional ID of the authenticated user performing the action.
 * @property timestamp    - ISO-8601 timestamp of when the event was recorded.
 * @property duration     - Wall-clock time in milliseconds for the entire operation.
 * @property status       - Whether the operation completed successfully or failed.
 * @property severity     - Anomaly classification assigned by the ML detector.
 * @property anomalyScore - Raw isolation-forest score; `0` during TRAINING mode.
 * @property details      - Arbitrary extra context attached by the caller.
 */
interface AuditLogMetadata {
    resource: string;
    functionName?: string;
    action: 'CREATE' | 'READ' | 'UPDATE' | 'DELETE' | 'UNKNOWN';
    userId?: string;
    timestamp: string;
    duration: number;
    status: 'SUCCESS' | 'FAILURE';
    severity: 'NORMAL' | 'SUSPICIOUS' | 'TRAINING';
    anomalyScore?: number;
    details?: Record<string, any>;
}
/**
 * A callback that receives every completed audit log entry.
 * Register one via {@link IntelligentAuditTrail.onLog} to forward logs to a
 * database, message queue, or any external sink without touching package code.
 *
 * @param payload - The fully-populated, immutable audit log entry.
 */
type AuditLogHandler = (payload: AuditLogMetadata) => void | Promise<void>;
/**
 * Manages the anomaly-detection lifecycle for the audit system.
 *
 * Operates in two modes:
 * - **TRAINING** – every event is written to `audit-baseline.jsonl` as normal
 *   behaviour; no anomaly scoring is performed.
 * - **PRODUCTION** – each event is scored by the isolation-forest detector,
 *   flagged as `SUSPICIOUS` when the score exceeds the learned threshold, and
 *   persisted to `audit-production.jsonl`.
 *
 * Instantiated as the module-level singleton {@link auditTrail}.
 */
declare class IntelligentAuditTrail {
    private detector;
    private mode;
    /** @internal — accessed by {@link emitAuditLog} via string key to avoid exposing in public types. */
    _handlers: AuditLogHandler[];
    /**
     * Registers a callback that is invoked for every emitted audit log entry,
     * regardless of severity or mode. Use this to forward logs to a database,
     * message queue, or external monitoring service **without modifying package
     * code**.
     *
     * Multiple handlers can be registered; they run in registration order.
     * Errors thrown inside a handler are caught and logged but do not affect
     * the audit flow.
     *
     * @param handler - The callback to invoke with each {@link AuditLogMetadata}.
     * @returns `this` for chaining.
     *
     * @example
     * ```ts
     * // In your app's bootstrap (e.g. instrumentation.ts)
     * auditTrail.onLog(async (log) => {
     *   await db.insert(auditLogs).values(log);
     * });
     * ```
     */
    onLog(handler: AuditLogHandler): this;
    /**
     * Sets the operating mode of the audit trail.
     *
     * @param mode - `'TRAINING'` to collect baseline data, or `'PRODUCTION'` to
     *   enable live anomaly detection and production log persistence.
     */
    setMode(mode: 'TRAINING' | 'PRODUCTION'): void;
    /**
     * Populates the anomaly-detection engine with pre-recorded baseline data and
     * switches the trail to `PRODUCTION` mode automatically.
     *
     * @param source - Either an array of {@link AuditLogMetadata} objects, or a
     *   file-system path to a `.jsonl` file where each line is a JSON-encoded log
     *   entry. Relative paths are resolved from `process.cwd()`.
     */
    loadBaseline(source: AuditLogMetadata[] | string): void;
    /**
     * Analyses a single audit event and returns its anomaly classification.
     *
     * Returns `{ severity: 'TRAINING', anomalyScore: 0 }` immediately when the
     * trail is in TRAINING mode.
     *
     * @param resource - The logical resource identifier (e.g. `'Article'`).
     * @param action   - The CRUD operation type for this event.
     * @param duration - Wall-clock duration of the operation in milliseconds.
     * @returns A partial {@link AuditLogMetadata} containing `severity` and
     *   `anomalyScore` fields ready to be merged into the final log entry.
     */
    processEvent(resource: string, action: AuditLogMetadata['action'], duration: number): Promise<Partial<AuditLogMetadata>>;
}
/**
 * Module-level singleton of {@link IntelligentAuditTrail}.
 * Import this instance to call {@link IntelligentAuditTrail.setMode},
 * {@link IntelligentAuditTrail.loadBaseline}, or
 * {@link IntelligentAuditTrail.onLog} during application startup.
 */
declare const auditTrail: IntelligentAuditTrail;
/**
 * Wraps an async function inside an audit context.
 *
 * Next.js `redirect()` and `notFound()` are treated as successful control-flow
 * rather than failures — they are logged with `status: 'SUCCESS'` and then
 * re-thrown so Next.js can process them normally.
 *
 * Prefer {@link auditServerAction} over calling this directly inside
 * `'use server'` files — it captures the function name automatically.
 *
 * @param actionFunc - The async function to audit.
 * @param options    - Configuration object.
 * @param options.resource     - Logical resource name written to every log entry.
 * @param options.functionName - Display name for the function; falls back to
 *   `'unknown'` when omitted.
 * @returns A new async function with the same signature as `actionFunc` that
 *   emits audit logs on every invocation.
 */
declare function withAudit<T extends any[], R>(actionFunc: (...args: T) => Promise<R>, options: {
    resource: string;
    functionName?: string;
}): (...args: T) => Promise<R>;
/**
 * Zero-boilerplate audit wrapper designed for use inside `'use server'` files.
 *
 * Reads `actionFunc.name` at definition time (before Next.js compilation or
 * minification can strip it) and passes it as `functionName` automatically.
 *
 * @example
 * ```ts
 * export const login = auditServerAction(
 *   async function login(formData: FormData) { ... },
 *   { resource: 'Auth' }  // functionName inferred as 'login'
 * );
 * ```
 *
 * @param actionFunc - The named async Server Action function to audit.
 * @param options    - Configuration object.
 * @param options.resource     - Logical resource name for every log entry.
 * @param options.functionName - Optional override; defaults to `actionFunc.name`.
 * @returns A wrapped async function with identical signature.
 */
declare function auditServerAction<T extends any[], R>(actionFunc: (...args: T) => Promise<R>, options: {
    resource: string;
    functionName?: string;
}): (...args: T) => Promise<R>;
/**
 * Wraps every method of a plain service object with {@link withAudit} via a
 * transparent {@link Proxy}.
 *
 * > **Important:** Does **not** work for `'use server'` modules. Use
 * > {@link auditServerAction} inside those files instead.
 *
 * @param actions      - The service object whose methods should be tracked.
 * @param resourceName - Logical resource name written to every log entry.
 * @returns A proxied version of `actions` where every function property is
 *   automatically wrapped with {@link withAudit}.
 */
declare function trackActions<T extends Record<string, any>>(actions: T, resourceName: string): T;

/**
 * Utility to convert raw Audit Metadata into numerical vectors for the ML model.
 * Features captured: [HourOfDay, ActionType, Duration, ResourceType]
 */
declare class AuditDataTransformer {
    private resourceMap;
    private actionMap;
    /**
     * Transforms a log entry into a numerical array.
     * Standardizing inputs is critical for Isolation Forest accuracy.
     */
    transform(resource: string, action: string, duration: number, timestamp: string): number[];
}
/**
 * Intelligent Anomaly Detector
 * Implements a preset baseline strategy for Review-by-Exception (RbE).
 */
declare class AuditAnomalyDetector {
    private model;
    private transformer;
    private isTrained;
    private dynamicThreshold;
    constructor();
    /**
     * Loads a preset baseline of 'Normal' activities.
     * Auto-calibrates the anomaly threshold based on the specific dataset distribution.
     */
    loadPresetBaseline(rawBaseline: Array<{
        resource: string;
        action: any;
        duration: number;
        timestamp: string;
    }>): void;
    /**
     * Analyzes a new activity against the baseline.
     * @returns score (0 to 1) and whether it exceeds the dynamic threshold.
     */
    analyzeActivity(resource: string, action: string, duration: number): {
        score: number;
        isSuspicious: boolean;
    };
}

export { AuditAnomalyDetector, AuditDataTransformer, type AuditLogHandler, type AuditLogMetadata, IntelligentAuditTrail, auditServerAction, auditTrail, trackActions, withAudit };
