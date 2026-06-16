/**
 * Ordered severity classification for every audit log entry.
 *
 * | Level      | Meaning                                                                    |
 * |------------|----------------------------------------------------------------------------|
 * | `DEBUG`    | Highly detailed diagnostics for developers — very low anomaly score.       |
 * | `INFO`     | Standard operational events representing normal, expected behaviour.       |
 * | `WARN`     | Unexpected events or potential issues that did not disrupt the application.|
 * | `ERROR`    | A specific operation or transaction failed.                                |
 * | `FATAL`    | Unrecoverable operation failure that may destabilise the service.          |
 * | `CRITICAL` | System-crashing event requiring immediate, human intervention.             |
 * | `TRAINING` | Controlled baseline sample ingested by the Isolation Forest model.         |
 *
 * **Automatic mapping (PRODUCTION mode):**
 * ```
 * │ status = SUCCESS     │ status = FAILURE
 * ──────────────────────────┼──────────────────────┼──────────────────
 * score ≤ 0.30              │ DEBUG                │ ERROR
 * normal range              │ INFO                 │ ERROR
 * threshold < s ≤ t+.05     │ WARN                 │ FATAL
 * threshold+.05 < s ≤ t+.10 │ ERROR                │ FATAL
 * threshold+.10 < s ≤ t+.20 │ FATAL                │ CRITICAL
 * score > threshold+.20     │ CRITICAL             │ CRITICAL
 * ──────────────────────────┴──────────────────────┴──────────────────
 * ```
 */
type AuditSeverity = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'FATAL' | 'CRITICAL' | 'TRAINING';
/**
 * Structured, explainable form of {@link AuditLogMetadata.message} emitted for
 * any event whose severity is `WARN`, `ERROR`, `FATAL`, or `CRITICAL`.
 *
 * This shape exists so that dashboards and alerting pipelines can render a
 * "why was this flagged?" panel without re-querying the database — every
 * number needed to explain the anomaly is already on the log line.
 *
 * @example
 * ```json
 * {
 * "summary": "Suspicious CREATE detected on Analyze via POST after 16200ms",
 * "duration_ms": 16200,
 * "p99_duration_ms": 2150,
 * "deviation": "+653%",
 * "hour": 14,
 * "typical_hours": [9, 10, 11, 12, 13, 15, 16],
 * "reason": "duration 16200ms > p99 threshold 2150ms for Analyze/CREATE. Hour 14 is within typical hours."
 * }
 * ```
 *
 * @property summary         - One-line human-readable summary (same text the
 * non-anomalous severities use as their plain-string `message`).
 * @property duration_ms     - Wall-clock duration of this event in ms.
 * @property p99_duration_ms - 99th-percentile baseline duration for this
 * `resource`/`action` pair; `undefined` when no baseline profile exists.
 * @property deviation       - Signed percentage difference between
 * `duration_ms` and `p99_duration_ms` (e.g. `"+653%"`); `undefined` when
 * `p99_duration_ms` is unavailable.
 * @property hour             - Hour of day (0-23) the event occurred in.
 * @property typical_hours    - Hours of day that are normal for this
 * `resource`/`action` pair, derived from the TRAINING baseline; `undefined`
 * when no baseline profile exists.
 * @property reason           - Plain-English explanation combining the
 * duration and hour-of-day signals; `undefined` when neither signal is
 * unusual (e.g. the anomaly was driven by resource/action novelty alone).
 */
interface AuditMessageDetail {
    summary: string;
    duration_ms: number;
    p99_duration_ms?: number;
    deviation?: string;
    hour: number;
    typical_hours?: number[];
    reason?: string;
}
/**
 * Complete metadata schema for a single audit log entry.
 *
 * Every field except `resource`, `action`, `timestamp`, `duration`, `status`,
 * and `severity` is optional and may be `null` when the runtime cannot resolve it.
 *
 * @property resource       - Logical resource being accessed (e.g. `'Auth'`, `'Article'`).
 * @property functionName   - Name of the backend function, API route, or component that triggered the event.
 * @property action         - CRUD operation detected for this event.
 * @property userId         - Database ID of the authenticated user;
 * auto-captured from authentication responses (e.g., Supabase Auth, Firebase Auth, Custom JWTs).
 * `null` for unauthenticated / anonymous requests. The sentinel value
 * `'SYSTEM'` is used instead of `null` when the event was produced by a
 * framework background process (e.g. Next.js Static Generation / ISR) rather
 * than a real anonymous visitor — see {@link resolveRequestContext}.
 * @property ipAddress      - Origin IP of the inbound HTTP request extracted from
 * `x-forwarded-for` or `x-real-ip` headers; `null` if unavailable.
 * @property userAgent      - `User-Agent` header from the inbound request; `null` if unavailable.
 * For background processes this is normalised to the constant string
 * `'system:background-process'` instead of the raw, misleading `'node'` UA.
 * @property message        - Auto-generated, human-readable summary of the event.
 * A plain string for `TRAINING` / `DEBUG` / `INFO` severities; an
 * {@link AuditMessageDetail} object for `WARN` / `ERROR` / `FATAL` / `CRITICAL`
 * severities, carrying the duration/percentile/hour signals that explain the
 * anomaly score.
 * @property httpMethod     - HTTP method of the relevant request (e.g. `'POST'`, `'GET'`).
 * @property urlPath        - URL path of the relevant request (e.g. `'/api/v1/articles'`).
 * For background processes this is normalised to the constant string
 * `'Background_Process'` for consistency across all events in the same render pass.
 * @property responseStatus - HTTP response status code (e.g. `200`, `403`, `500`).
 * @property timestamp      - ISO-8601 timestamp when the event was recorded.
 * @property duration       - Wall-clock duration in milliseconds for the entire operation.
 * @property status         - Whether the operation completed successfully or threw an error.
 * @property severity       - Severity classification assigned by the ML detector.
 * @property anomalyScore   - Raw Isolation-Forest score in `[0, 1]`; `0` during TRAINING mode.
 * @property details        - Arbitrary extra context (e.g. error messages, per-call breakdown).
 * @property tableName      - Name of the affected database table / collection
 * (for UPDATE/DELETE). Only populated when {@link recordFieldChange} was
 * called for an `auditRules`-enabled field, or when the resource rule sets
 * `captureTableName`.
 * @property fieldName      - Name of the specific column / field being
 * changed. Only populated alongside `oldValue`/`newValue` when explicitly
 * enabled via {@link auditRules} — never logged unconditionally.
 * @property oldValue       - Sanitised, possibly-truncated value before the
 * change. Only present when {@link recordFieldChange} was called **and** the
 * corresponding {@link AuditFieldRule.capture} is `true`. Never logged for
 * fields without an explicit opt-in rule.
 * @property newValue       - Sanitised, possibly-truncated value after the
 * change. Same opt-in rules as `oldValue`.
 * @property payload        - Full request/response payload — only present
 * when {@link recordPayload} was called **and**
 * {@link AuditResourceRules.captureFullPayload} is `true` for the resource.
 * Used sparingly (e.g. inbound webhooks), and always sanitised + size-capped.
 */
interface AuditLogMetadata {
    resource: string;
    functionName?: string;
    action: 'CREATE' | 'READ' | 'UPDATE' | 'DELETE' | 'UNKNOWN';
    userId?: string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
    message?: string | AuditMessageDetail;
    httpMethod?: string | null;
    urlPath?: string | null;
    responseStatus?: number | null;
    timestamp: string;
    duration: number;
    status: 'SUCCESS' | 'FAILURE';
    severity: AuditSeverity;
    anomalyScore?: number;
    details?: Record<string, unknown>;
    tableName?: string;
    fieldName?: string;
    recordId?: string | number;
    oldValue?: unknown;
    newValue?: unknown;
    payload?: unknown;
}
/**
 * Callback invoked for every completed audit log entry regardless of severity or mode.
 * Register via {@link IntelligentAuditTrail.onLog} to forward entries to a database
 * (PostgreSQL, MySQL, Firestore), message queue, or external monitoring sink.
 *
 * @param payload - Fully-populated, immutable audit log entry.
 */
type AuditLogHandler = (payload: AuditLogMetadata) => void | Promise<void>;
/**
 * Capture rule for a single database column / object field.
 *
 * Per the **opt-in, scoped, sanitised** design principle, `oldValue` /
 * `newValue` are only ever written to the audit log for fields whose rule has
 * `capture: true`. Fields without a rule (or with `capture: false`) are
 * silently skipped by {@link recordFieldChange} — no `fieldName`, `oldValue`,
 * or `newValue` is emitted for them.
 *
 * @property capture   - Whether to log `oldValue`/`newValue` for this field.
 * Defaults to `false` (not captured) when no rule is registered at all.
 * @property redact     - When `true`, both `oldValue` and `newValue` are
 * replaced with the literal string `'[REDACTED]'` regardless of `capture`.
 * Use for fields that are sensitive but whose *presence* of a change is
 * still worth recording (e.g. `password`, `apiKey`).
 * @property maxLength  - Truncates string values longer than this many
 * characters, appending `'…'`.
 */
interface AuditFieldRule {
    capture?: boolean;
    redact?: boolean;
    maxLength?: number;
}
/**
 * Capture rules for an entire logical resource / database table.
 *
 * @property captureTableName   - Whether {@link recordFieldChange} should
 * populate {@link AuditLogMetadata.tableName}. Defaults to `true`.
 * @property captureFullPayload - Whether {@link recordPayload} is allowed to
 * populate {@link AuditLogMetadata.payload} for this resource. Defaults to
 * `false` — full payloads should be the exception, not the rule (e.g.
 * inbound webhooks where the entire body is the audit-worthy artifact).
 * @property maxPayloadSize     - Maximum serialised payload size in bytes
 * before truncation. Defaults to `2048`.
 * @property fields             - Per-field {@link AuditFieldRule} map keyed
 * by field/column name.
 */
interface AuditResourceRules {
    captureTableName?: boolean;
    captureFullPayload?: boolean;
    maxPayloadSize?: number;
    fields?: Record<string, AuditFieldRule>;
}
/**
 * Central, mutable registry of {@link AuditResourceRules} keyed by resource /
 * table name. Empty by default — **nothing is captured until the developer
 * opts in** by populating this object at application bootstrap.
 *
 * @example
 * ```ts
 * import { auditRules } from 'intelligent-audit-trail';
 *
 * auditRules.articles = {
 * captureTableName: true,
 * fields: {
 * title:  { capture: true, maxLength: 200 },
 * status: { capture: true },
 * // 'content' intentionally omitted — never logged
 * },
 * };
 *
 * auditRules.users = {
 * captureTableName: true,
 * fields: {
 * role:     { capture: true },
 * email:    { capture: false, redact: true },
 * password: { redact: true }, // never logs the value, even if captured
 * },
 * };
 *
 * // High-risk inbound webhook — payload logging used sparingly & capped.
 * auditRules.webhookIncoming = {
 * captureTableName: false,
 * captureFullPayload: true,
 * maxPayloadSize: 4096,
 * };
 * ```
 */
declare const auditRules: Record<string, AuditResourceRules>;
/**
 * Recursively sanitises a value before it is written to the audit log:
 * - Applies {@link AuditFieldRule.redact} / `maxLength` at the top level.
 * - Recurses into plain objects/arrays, redacting any key matching
 * {@link ALWAYS_REDACT_KEYS} (`password`, `token`, `secret`, `apiKey`,
 * `authorization`) regardless of the rule passed in.
 *
 * @param value - The raw value to sanitise (e.g. an old/new column value, or
 * a full request payload).
 * @param rule  - Optional top-level {@link AuditFieldRule} controlling
 * redaction/truncation of `value` itself.
 * @returns A sanitised, JSON-serialisable copy of `value`.
 */
declare function sanitizeValue(value: unknown, rule?: AuditFieldRule): unknown;
/**
 * HTTP request metadata captured once per inbound request and carried through
 * {@link AsyncLocalStorage} (via {@link captureRequestContext}) or resolved on
 * demand from Web Framework headers (Next.js, Express, Laravel bridges).
 *
 * @internal
 */
interface RequestContext {
    /** Client IP extracted from `x-forwarded-for` or `x-real-ip`. */
    ipAddress: string | null;
    /** `User-Agent` header value. */
    userAgent: string | null;
    /** HTTP method of the inbound request (e.g. `'POST'`). */
    httpMethod: string | null;
    /** Pathname component of the inbound request URL. */
    urlPath: string | null;
    /** Sniffed User ID from incoming cookies or headers */
    incomingUserId: string | null;
}
/**
 * Per-invocation state propagated through {@link networkQueryTracker} for the
 * duration of a single {@link withAudit}-wrapped function call.
 *
 * @internal
 */
interface AuditContext {
    /** CRUD actions detected from outgoing fetch calls (Database, External APIs). */
    actions: Set<AuditLogMetadata['action']>;
    /** Display name of the wrapped function. */
    functionName: string;
    /** Logical resource name provided to {@link withAudit}. */
    resource: string;
    /**
     * User ID auto-captured by the fetch interceptor from auth responses.
     * Remains `null` for unauthenticated (anonymous) requests.
     */
    capturedUserId: string | null;
    /** Explicit URL override passed via options to bypass framework limitations. */
    overrideUrlPath?: string | null;
    /** Fallback URL tracked from the intercepted fetch if request context fails. */
    lastRequestUrl?: string | null;
    /** Fallback HTTP method tracked from the intercepted fetch. */
    lastHttpMethod?: string | null;
    /**
     * Field-level before/after changes recorded via {@link recordFieldChange}
     * during this invocation. Only the **first** entry is merged into the
     * emitted log (see {@link withAudit}) — if multiple fields changed in one
     * operation, call {@link recordFieldChange} once for the most relevant one,
     * or inspect `details` for the full set via a custom {@link AuditLogHandler}.
     */
    capturedFieldChanges?: Array<{
        tableName: string;
        fieldName: string;
        recordId?: string | number;
        oldValue: unknown;
        newValue: unknown;
    }>;
    /**
     * Sanitised, size-capped payload recorded via {@link recordPayload} during
     * this invocation. Merged into {@link AuditLogMetadata.payload} when present.
     */
    capturedPayload?: unknown;
}
/**
 * Retrieves the currently active Audit Context and Request Context.
 * Safely allows developers to access the inferred `userId`, `ipAddress`, and
 * active tracking metadata from anywhere deep inside the call stack without
 * prop-drilling.
 *
 * @returns An object containing `auditCtx` and `reqCtx`, or `null` if called
 * outside of a valid tracking boundary.
 */
declare function getAuditContext(): Promise<{
    auditCtx: AuditContext | null;
    reqCtx: RequestContext;
}>;
/**
 * Records a single before/after field change for the **current**
 * {@link withAudit} / {@link auditServerAction} / {@link auditHandler}
 * invocation, to be merged into the emitted log as `tableName`, `fieldName`,
 * `oldValue`, and `newValue`.
 *
 * **Strictly opt-in:** if no matching `capture: true` rule exists in
 * {@link auditRules} for `tableName`/`fieldName`, this call is a silent no-op
 * — nothing is added to the log. This guarantees `oldValue`/`newValue` (and
 * therefore `fieldName`) are never written unconditionally, avoiding PII
 * leaks and log bloat for columns nobody asked to track.
 *
 * Values are passed through {@link sanitizeValue} using the matched
 * {@link AuditFieldRule} before being stored.
 *
 * Only the **first** recorded change per invocation is merged into the log
 * line; call this once for the most security/audit-relevant field of the
 * operation (e.g. `role` on a `users` update), not once per changed column.
 *
 * @param tableName - Database table / collection name (e.g. `'articles'`).
 * @param fieldName - Column / field name (e.g. `'status'`).
 * @param oldValue  - Value before the change.
 * @param newValue  - Value after the change.
 * @param recordId  - Optional Primary Key / ID of the modified row.
 *
 * @example
 * ```ts
 * export const updateArticle = auditServerAction(async function updateArticle(id: string, data: ArticlePatch) {
 * const before = await db.article.findUnique({ where: { id } });
 * const updated = await db.article.update({ where: { id }, data });
 *
 * recordFieldChange('articles', 'status', before?.status, updated.status);
 * return updated;
 * }, { resource: 'Article' });
 * ```
 */
declare function recordFieldChange(tableName: string, fieldName: string, oldValue: unknown, newValue: unknown, recordId?: string | number): void;
/**
 * Records a sanitised, size-capped payload for the **current**
 * {@link withAudit} / {@link auditHandler} invocation, to be merged into the
 * emitted log as {@link AuditLogMetadata.payload}.
 *
 * **Used sparingly:** this is a no-op unless
 * `auditRules[resource].captureFullPayload === true`. Reserve this for
 * high-signal, low-volume operations (inbound webhooks, admin RPCs) — never
 * for routine CRUD, where {@link recordFieldChange} is the correct tool.
 *
 * The payload is deep-sanitised via {@link sanitizeValue} (redacting
 * `password`/`token`/`secret`/`apiKey`/`authorization` keys at any depth) and
 * then size-capped to `auditRules[resource].maxPayloadSize` bytes (default
 * `2048`); oversized payloads are replaced with a truncated JSON string
 * suffixed `'...[truncated]'`.
 *
 * @param resource - Logical resource name matching a key in {@link auditRules}.
 * @param payload  - The raw request/response body to (conditionally) capture.
 *
 * @example
 * ```ts
 * export const POST = auditHandler(async function webhookIncoming(request: Request) {
 * const body = await request.json();
 * recordPayload('webhookIncoming', body);
 * // ... process webhook ...
 * }, { resource: 'webhookIncoming' });
 * ```
 */
declare function recordPayload(resource: string, payload: unknown): void;
/**
 * Manages the anomaly-detection lifecycle, severity classification, and log
 * routing for the entire audit system.
 *
 * Operates in two modes that switch automatically:
 *
 * - **TRAINING** — every event is written to `audit-baseline.jsonl`; no ML scoring.
 * Severity is always `'TRAINING'`.
 * - **PRODUCTION** — every event is scored by the Isolation Forest; severity is
 * derived from the score, the dynamic threshold, and the operation status.
 * Logs are persisted to `audit-production.jsonl`.
 *
 * Instantiated as the module-level singleton {@link auditTrail}.
 * Switch modes by calling {@link loadBaseline} (moves to PRODUCTION automatically)
 * or {@link setMode} explicitly.
 */
declare class IntelligentAuditTrail {
    private detector;
    private mode;
    /**
     * @internal — accessed by {@link emitAuditLog} via string key to avoid
     * exposing the handler list in the public type surface.
     */
    _handlers: AuditLogHandler[];
    /**
     * Registers a callback invoked for every emitted audit log entry regardless
     * of severity or mode. Use this to forward entries to a database, message
     * queue, or external monitoring service without modifying package internals.
     *
     * Multiple handlers may be registered and run in registration order.
     * Errors thrown inside a handler are caught and logged but do not interrupt
     * the audit pipeline.
     *
     * @param handler - Callback receiving each {@link AuditLogMetadata}.
     * @returns `this` for chaining.
     *
     * @example
     * ```ts
     * // index.ts
     * auditTrail.onLog(async (log) => {
     * await db.insert(auditLogs).values({
     * resource:        log.resource,
     * function_name:   log.functionName,
     * action:          log.action,
     * user_id:         log.userId,
     * ip_address:      log.ipAddress,
     * user_agent:      log.userAgent,
     * message:         log.message,
     * http_method:     log.httpMethod,
     * url_path:        log.urlPath,
     * response_status: log.responseStatus,
     * timestamp:       log.timestamp,
     * duration:        log.duration,
     * status:          log.status,
     * severity:        log.severity,
     * anomaly_score:   log.anomalyScore,
     * details:         log.details,
     * table_name:      log.tableName,
     * field_name:      log.fieldName,
     * old_value:       log.oldValue,
     * new_value:       log.newValue,
     * payload:         log.payload,
     * });
     * });
     * ```
     */
    onLog(handler: AuditLogHandler): this;
    /**
     * Sets the operating mode of the audit trail.
     *
     * Prefer {@link loadBaseline} over calling `setMode('PRODUCTION')` directly,
     * as `loadBaseline` also trains the Isolation Forest model before switching.
     *
     * @param mode - `'TRAINING'` to collect baseline data; `'PRODUCTION'` to
     * enable live anomaly detection.
     */
    setMode(mode: 'TRAINING' | 'PRODUCTION'): void;
    /**
     * Trains the Isolation Forest on pre-recorded baseline data and automatically
     * switches the trail to `PRODUCTION` mode.
     *
     * By using a Promise, Deno and Node can evaluate the file system imports dynamically
     * bypassing Turbopack static compilation blockages on the client-side.
     *
     * @param source - Either an array of {@link AuditLogMetadata} objects, or a
     * relative or absolute file-system path to a `.jsonl` file where each line
     * is a JSON-encoded log entry. Relative paths are resolved from `process.cwd()`.
     */
    loadBaseline(source: AuditLogMetadata[] | string): Promise<void>;
    /**
     * Maps an Isolation Forest score, the current dynamic threshold, and the
     * operation status to an {@link AuditSeverity} level.
     *
     * The threshold bands above the calibrated threshold are:
     * - `+0.00` to `+0.05` → WARN
     * - `+0.05` to `+0.10` → ERROR
     * - `+0.10` to `+0.20` → FATAL
     * - `> +0.20`          → CRITICAL
     *
     * @param score        - Raw Isolation Forest anomaly score `[0, 1]`.
     * @param isSuspicious - Pre-computed flag (`score > threshold`).
     * @param status       - Operation outcome.
     * @returns The appropriate {@link AuditSeverity} for this event.
     *
     * @internal
     */
    private computeSeverity;
    /**
     * Scores a single audit event and returns its severity classification.
     *
     * Returns `{ severity: 'TRAINING', anomalyScore: 0 }` immediately when the
     * trail is in `TRAINING` mode or when the model has not yet been trained.
     *
     * @param resource - Logical resource identifier (e.g. `'Article'`).
     * @param action   - CRUD operation type for this event.
     * @param duration - Wall-clock duration of the operation in milliseconds.
     * @param status   - Operation outcome; defaults to `'SUCCESS'`.
     * @returns Severity classification and raw anomaly score.
     */
    processEvent(resource: string, action: AuditLogMetadata['action'], duration: number, status?: 'SUCCESS' | 'FAILURE'): Promise<{
        severity: AuditSeverity;
        anomalyScore: number;
    }>;
    /**
     * Builds the structured {@link AuditMessageDetail} for an anomalous
     * (`WARN`+) event, combining:
     * - the plain-English `summary` (same text non-anomalous events use as
     * their entire `message`),
     * - `duration_ms` for this event,
     * - `p99_duration_ms` / `typical_hours` from the TRAINING baseline profile
     * for this `resource`/`action` pair (via
     * {@link AuditAnomalyDetector.getDurationStats}),
     * - a signed `deviation` percentage vs. the p99 baseline, and
     * - a plain-English `reason` combining the duration and hour-of-day signals.
     *
     * When no baseline profile exists for this `resource`/`action` pair (e.g.
     * a brand-new endpoint), `p99_duration_ms`, `typical_hours`, `deviation`,
     * and `reason` are all omitted — the anomaly was driven by resource/action
     * novelty itself, which the model captures but this explainer cannot phrase
     * in terms of duration/time-of-day.
     *
     * @param resource - Logical resource identifier (e.g. `'Article'`).
     * @param action   - CRUD operation type for this event.
     * @param duration - Wall-clock duration of the operation in milliseconds.
     * @param summary  - Pre-built one-line summary (see {@link generateSummary}).
     * @returns A fully-populated {@link AuditMessageDetail}.
     */
    explainAnomaly(resource: string, action: AuditLogMetadata['action'], duration: number, summary: string): AuditMessageDetail;
}
/**
 * Module-level singleton of {@link IntelligentAuditTrail}.
 *
 * Import this instance during application bootstrap to configure the trail:
 * ```ts
 * // startup.ts
 * import { auditTrail } from 'intelligent-audit-trail';
 *
 * export async function register() {
 * auditTrail.loadBaseline('audit-baseline.jsonl');   // switches to PRODUCTION
 * auditTrail.onLog(async (log) => { await db.insert(...) });
 * }
 * ```
 */
declare const auditTrail: IntelligentAuditTrail;
/**
 * Wraps an async function with an explicit {@link RequestContext} derived from
 * an inbound HTTP request object.
 *
 * **Automatically captures:**
 * - `ipAddress`  — from `x-forwarded-for` or `x-real-ip` headers
 * - `userAgent`  — from the `User-Agent` header
 * - `httpMethod` — HTTP method of the inbound request
 * - `urlPath`    — pathname of the inbound request URL
 *
 * Once set, every {@link withAudit}-wrapped call that executes within `fn`
 * will inherit these values without any additional configuration.
 *
 * > **Note for App Frameworks:** Request contexts can be captured globally.
 * > Use `captureRequestContext` when you need accurate behaviour in Express,
 * > Fastify, Laravel NodeJS Bridges, or custom servers.
 *
 * @param request - Any object whose `headers` property exposes a `get()` method
 * compatible with the Fetch API `Request` or the Node.js `http.IncomingMessage`
 * adapter (e.g. Express `req` with `req.headers.get`). The `method` and `url`
 * fields are read if present.
 * @param fn      - Async function to execute inside the captured context.
 * @returns The resolved value of `fn`.
 *
 * @example
 * ```ts
 * // Express middleware
 * app.use((req, _res, next) => {
 * // Adapt Node IncomingMessage to Fetch-style headers
 * const headers = { get: (k: string) => req.headers[k.toLowerCase()] as string ?? null };
 * captureRequestContext({ headers, method: req.method, url: req.url }, next);
 * });
 * ```
 */
declare function captureRequestContext<T>(request: {
    headers: {
        get(key: string): string | null | undefined;
    };
    method?: string;
    url?: string;
}, fn: () => Promise<T>): Promise<T>;
/**
 * Permanently binds a URL path to the **current async execution context** so
 * that every subsequent {@link withAudit} or {@link auditServerAction} call
 * running in the same logical request records it as `urlPath` — without
 * requiring each action to be passed the path explicitly.
 *
 * This is the lightest-weight path-propagation mechanism available: one call
 * in your middleware is enough to cover every downstream server action,
 * service method, or database query executed inside that request.
 *
 * ### When to use
 * - **Server Actions called from Server Components** — there is no HTTP
 * referer, so `next/headers` cannot infer the originating page.
 * - **Express / Fastify / Hono / Elysia / Laravel Octane (Node bridge)** —
 * place one call in your global middleware to propagate the route path.
 * - **Vue SSR / Nuxt server routes** — call inside the server event handler.
 * - **Firebase Cloud Functions / Cloudflare Workers** — call at the top of
 * the handler before any async work begins.
 *
 * > **Note:** Uses `AsyncLocalStorage.enterWith()` which mutates the current
 * > async context in place. This is intentional for middleware scenarios and
 * > is safe as long as the call happens at the very start of a new request.
 * > If you need strict scoping, use {@link captureRequestContext} instead.
 *
 * @param path - Application route path to record (e.g. `'/dashboard'`,
 * `'/blog/[slug]'`). Should be the page/route path, not an API endpoint.
 *
 * @example
 * ```ts
 * // Next.js middleware (middleware.ts)
 * import { NextResponse, type NextRequest } from 'next/server';
 * import { setCurrentPath } from 'intelligent-audit-trail';
 *
 * export function middleware(request: NextRequest) {
 * setCurrentPath(request.nextUrl.pathname);
 * return NextResponse.next();
 * }
 * ```
 *
 * @example
 * ```ts
 * // Express global middleware
 * import { setCurrentPath } from 'intelligent-audit-trail';
 *
 * app.use((req, _res, next) => {
 * setCurrentPath(req.path);
 * next();
 * });
 * ```
 *
 * @example
 * ```ts
 * // Nuxt 3 / H3 server middleware (server/middleware/audit.ts)
 * import { setCurrentPath } from 'intelligent-audit-trail';
 * import { defineEventHandler, getRequestURL } from 'h3';
 *
 * export default defineEventHandler((event) => {
 * setCurrentPath(getRequestURL(event).pathname);
 * });
 * ```
 *
 * @example
 * ```ts
 * // Hono middleware
 * import { setCurrentPath } from 'intelligent-audit-trail';
 *
 * app.use('*', async (c, next) => {
 * setCurrentPath(new URL(c.req.url).pathname);
 * await next();
 * });
 * ```
 */
declare function setCurrentPath(path: string): void;
/**
 * The single, unified wrapper for all Backend Operations (Server Actions, API Routes, RPCs).
 *
 * Automatically detects whether the executed function is receiving a Web `Request`
 * (API Routes) or raw data (Server Actions) and captures the context accordingly.
 * * It automatically infers the Resource and Action from the function name if you choose
 * to omit the `options` parameter.
 *
 * @example
 * ```ts
 * // 1. API Route Example
 * export const POST = audit(async function analyzeRoute(request: Request) { ... });
 * * // 2. Server Action Example
 * export const updateArticle = audit(async function updateArticle(data) { ... });
 * ```
 */
declare function audit<T extends unknown[], R>(targetFunc: (...args: T) => Promise<R>, options?: {
    resource?: string;
    functionName?: string;
    urlPath?: string;
    action?: AuditLogMetadata['action'];
}): (...args: T) => Promise<R>;
declare const auditHandler: typeof audit;
declare const auditServerAction: typeof audit;
/**
 * Zero-boilerplate audit wrapper specifically designed for **React Server Components (Pages)**.
 */
declare function auditPage<T extends (...args: any[]) => any>(pageComponent: T, options?: {
    resource?: string;
    functionName?: string;
    urlPath?: string;
    action?: AuditLogMetadata['action'];
}): T;
/**
 * Wraps every method of a plain service object with the unified `audit` wrapper.
 */
declare function trackActions<T extends Record<string, unknown>>(actions: T, resourceName: string): T;
/**
 * Generic Change Data Capture (CDC) Webhook Receiver for PostgreSQL / MySQL.
 * * Used to achieve ZERO latency tracking inside your application layer. Just point
 * your external database triggers (or Kafka/Debezium sinks) to this endpoint!
 * * Mount this inside an API Route (e.g. `/app/api/audit-webhook/route.ts`):
 * ```ts
 * import { auditWebhookReceiver } from 'intelligent-audit-trail';
 * export const POST = auditWebhookReceiver;
 * ```
 */
declare const auditWebhookReceiver: (request: Request) => Promise<Response>;

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
declare class AuditDataTransformer {
    private resourceMap;
    /**
     * Maps CRUD action strings to their ordinal representation.
     * Unknown actions fall back to `0`.
     */
    private readonly actionMap;
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
    transform(resource: string, action: string, duration: number, timestamp: string): number[];
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
declare class AuditAnomalyDetector {
    private model;
    private transformer;
    private isTrained;
    /**
     * Auto-calibrated anomaly threshold.
     * Initialised conservatively at `0.60`; overwritten by {@link loadPresetBaseline}.
     */
    private dynamicThreshold;
    /**
     * Per-`resource:action` duration & hour-of-day profiles built from the
     * TRAINING baseline. Synthetic outliers are intentionally **excluded** so
     * that `p99` reflects genuinely-observed traffic, not injected extremes.
     *
     * @internal
     */
    private durationProfiles;
    constructor();
    /**
     * The current anomaly decision threshold used by {@link analyzeActivity}.
     *
     * Exposed so that {@link IntelligentAuditTrail} can compute granular severity
     * bands (WARN / ERROR / FATAL / CRITICAL) without duplicating logic.
     *
     * @returns A score in the range `[0, 1]` above which an event is flagged.
     */
    get threshold(): number;
    /**
     * Builds the `resource:action` key used to index {@link durationProfiles}.
     * @internal
     */
    private profileKey;
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
    loadPresetBaseline(rawBaseline: Array<{
        resource: string;
        action: string;
        duration: number;
        timestamp: string;
    }>): void;
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
    };
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
    analyzeActivity(resource: string, action: string, duration: number): {
        score: number;
        isSuspicious: boolean;
    };
}

export { AuditAnomalyDetector, type AuditContext, AuditDataTransformer, type AuditFieldRule, type AuditLogHandler, type AuditLogMetadata, type AuditMessageDetail, type AuditResourceRules, type AuditSeverity, IntelligentAuditTrail, type RequestContext, audit, auditHandler, auditPage, auditRules, auditServerAction, auditTrail, auditWebhookReceiver, captureRequestContext, getAuditContext, recordFieldChange, recordPayload, sanitizeValue, setCurrentPath, trackActions };
