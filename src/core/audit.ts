/* ./src/core/audit.ts */
import { AuditAnomalyDetector } from '../models/isolation-forest';

/**
 * A lightweight, synchronous polyfill for Node.js `AsyncLocalStorage`.
 *
 * This fallback is used exclusively in browser or edge environments where the 
 * native `async_hooks` module is unavailable. It provides strict API compatibility 
 * to prevent runtime crashes when client-side frameworks (like React or Vue) 
 * evaluate the audit trail library.
 *
 * @typeParam T - The type of the context state being stored.
 * @internal
 */
class BrowserAsyncLocalStorage<T> {
  private store: T | undefined;
  getStore(): T | undefined { 
  /**
   * Retrieves the currently active store context.
   *
   * @returns The active store context, or `undefined` if none is set.
   */
    return this.store; 
  }
  /**
   * Runs a callback function within the provided store context.
   *
   * @param store - The context state to activate.
   * @param callback - The function to execute while the context is active.
   * @returns The return value of the provided callback.
   */
  run(store: T, callback: () => any) {
    this.store = store;
    return callback();
  }
  /**
   * Transitions the current execution context into the provided store state
   * for the remainder of the synchronous execution.
   *
   * @param store - The context state to activate.
   */
  enterWith(store: T) { this.store = store; }
}

/**
 * The environment-aware `AsyncLocalStorage` constructor.
 *
 * This variable dynamically resolves at runtime:
 * - Server (Node.js): Resolves to the native `async_hooks.AsyncLocalStorage`.
 * - Client (Browser): Resolves to the {@link BrowserAsyncLocalStorage} polyfill.
 *
 * @internal
 */
let ResolvedAsyncLocalStorage: any = BrowserAsyncLocalStorage;

if (typeof window === 'undefined') {
  try {
    if (typeof require !== 'undefined') {
      // @ts-ignore
      const async_hooks = require('async_hooks' + '');
      ResolvedAsyncLocalStorage = async_hooks.AsyncLocalStorage;
    }
  } catch (e) {
    ResolvedAsyncLocalStorage = BrowserAsyncLocalStorage;
  }
}

// ─── Severity ─────────────────────────────────────────────────────────────────

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
export type AuditSeverity =
  | 'DEBUG'
  | 'INFO'
  | 'WARN'
  | 'ERROR'
  | 'FATAL'
  | 'CRITICAL'
  | 'TRAINING';

// ─── AuditMessageDetail ────────────────────────────────────────────────────────

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
export interface AuditMessageDetail {
  summary: string;
  duration_ms: number;
  p99_duration_ms?: number;
  deviation?: string;
  hour: number;
  typical_hours?: number[];
  reason?: string;
}

// ─── AuditLogMetadata ─────────────────────────────────────────────────────────

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
export interface AuditLogMetadata {
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
export type AuditLogHandler = (payload: AuditLogMetadata) => void | Promise<void>;

// ─── Field Change & Payload Capture Configuration ─────────────────────────────

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
export interface AuditFieldRule {
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
export interface AuditResourceRules {
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
export const auditRules: Record<string, AuditResourceRules> = {};

/** Field names that are always redacted, regardless of {@link auditRules}. */
const ALWAYS_REDACT_KEYS = new Set(['password', 'token', 'secret', 'apikey', 'authorization']);

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
export function sanitizeValue(value: unknown, rule?: AuditFieldRule): unknown {
  if (value === undefined || value === null) return value;
  if (rule?.redact) return '[REDACTED]';

  if (typeof value === 'string') {
    if (rule?.maxLength && value.length > rule.maxLength) {
      return value.slice(0, rule.maxLength) + '…';
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(v => sanitizeValue(v));
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      if (ALWAYS_REDACT_KEYS.has(key.toLowerCase())) {
        out[key] = '[REDACTED]';
        continue;
      }
      out[key] = sanitizeValue(v);
    }
    return out;
  }

  return value;
}

// ─── Internal Context Types ───────────────────────────────────────────────────

/**
 * HTTP request metadata captured once per inbound request and carried through
 * {@link AsyncLocalStorage} (via {@link captureRequestContext}) or resolved on
 * demand from Web Framework headers (Next.js, Express, Laravel bridges).
 *
 * @internal
 */
export interface RequestContext {
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
export interface AuditContext {
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

// ─── AsyncLocalStorage Singletons ─────────────────────────────────────────────

/**
 * Propagates {@link AuditContext} across async boundaries within one
 * {@link withAudit} invocation.
 *
 * @internal
 */
const networkQueryTracker: BrowserAsyncLocalStorage<AuditContext> | any = new (ResolvedAsyncLocalStorage as any)();

/**
 * Carries {@link RequestContext} set explicitly by {@link captureRequestContext}.
 * When empty, {@link resolveRequestContext} falls back to Framework Specific headers.
 *
 * @internal
 */
const requestContextStorage: BrowserAsyncLocalStorage<RequestContext> | any = new (ResolvedAsyncLocalStorage as any)();

// ─── Public Context Helpers ───────────────────────────────────────────────────

/**
 * Retrieves the currently active Audit Context and Request Context.
 * Safely allows developers to access the inferred `userId`, `ipAddress`, and
 * active tracking metadata from anywhere deep inside the call stack without
 * prop-drilling.
 *
 * @returns An object containing `auditCtx` and `reqCtx`, or `null` if called
 * outside of a valid tracking boundary.
 */
export async function getAuditContext(): Promise<{ auditCtx: AuditContext | null; reqCtx: RequestContext }> {
  const reqCtx = await resolveRequestContext();
  const auditCtx = networkQueryTracker.getStore() || null;
  return { auditCtx, reqCtx };
}

// ─── Field Change & Payload Recording ─────────────────────────────────────────

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
export function recordFieldChange(
  tableName: string,
  fieldName: string,
  oldValue: unknown,
  newValue: unknown,
  recordId?: string | number,
): void {
  const ctx = networkQueryTracker.getStore();
  if (!ctx) return;

  const resourceRules = auditRules[tableName];
  const fieldRule = resourceRules?.fields?.[fieldName];

  // Strict opt-in: silently skip unless explicitly enabled for this field.
  if (!fieldRule?.capture) return;

  if (!ctx.capturedFieldChanges) ctx.capturedFieldChanges = [];
  ctx.capturedFieldChanges.push({
    tableName,
    fieldName,
    recordId,
    oldValue: sanitizeValue(oldValue, fieldRule),
    newValue: sanitizeValue(newValue, fieldRule),
  });
}

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
export function recordPayload(resource: string, payload: unknown): void {
  const ctx = networkQueryTracker.getStore();
  if (!ctx) return;

  const rules = auditRules[resource];
  if (!rules?.captureFullPayload) return;

  const maxBytes = rules.maxPayloadSize ?? 2048;
  const sanitised = sanitizeValue(payload);

  try {
    const serialised = JSON.stringify(sanitised);
    if (serialised.length > maxBytes) {
      ctx.capturedPayload = serialised.slice(0, Math.max(0, maxBytes - 16)) + '..."[truncated]"';
      return;
    }
    ctx.capturedPayload = sanitised;
  } catch {
    ctx.capturedPayload = '[unserialisable payload]';
  }
}

// ─── Deep Stack Sniffers (V2) ─────────────────────────────────────────────────

/**
 * Parses the V8 stack trace to find the original calling function's name.
 * Used as an automatic fallback when an action (like a standalone REST fetch)
 * isn't explicitly wrapped in `withAudit`.
 *
 * @returns The inferred function name or `'Standalone_Action'`.
 * @internal
 */
function inferCallerFunctionName(): string {
  try {
    const err = new Error();
    const stack = err.stack?.split('\n') || [];
    for (let i = 2; i < stack.length; i++) {
      const line = stack[i];
      // Skip internal node modules, node internals, Next.js internal dist, and this audit file itself
      if (
        !line.includes('intelligent-audit-trail') &&
        !line.includes('node:internal') &&
        !line.includes('node_modules') &&
        !line.includes('next/dist') && 
        !line.includes('audit.ts')
      ) {
        // Matches standard named functions or class methods
        const match = line.match(/at\s+(?:async\s+)?(?:[^\s]+\.)?([a-zA-Z0-9_$]+)\s*(?:\[as\s+[^\]]+\])?\s*\(/) 
                   || line.match(/at\s+([a-zA-Z0-9_$]+)\s+\(/);
        if (match && match[1]) {
          const fnName = match[1];
          // Explicitly ignore JS engine async boundaries and wrappers to trace back to user code
          const ignoredWrappers = [
            'fetch', 'eval', 'setTimeout', 'Promise', 'Object', 'Array',
            'Module', 'NextNodeServer', 'runMicrotasks', 'processTicksAndRejections',
            'asyncGeneratorStep', '_next', 'invoke', 'eventLoopTick', 
            'processImmediate', 'processNextTick', 'callFn', 'callCallback', 
            'bound', 'tryCatch', 'Generator', 'NextJS', 'React'
          ];
          
          if (!ignoredWrappers.includes(fnName)) {
            return fnName;
          }
        }
      }
    }
  } catch {
    /* silently ignore stack parse errors on unsupported JS engines */
  }
  return 'Standalone_Action';
}

/**
 * Magical Next.js Server Component Route Sniffer.
 * When Next.js violently strips URL headers across the Edge-to-Node boundary, this rips
 * through the V8 Stack Trace to find the compiled `page.tsx` or `route.ts`
 * that initiated the call and reconstructs the URL path from the file system.
 *
 * @internal
 */
function inferUrlPathFromStack(): string | null {
  try {
    const err = new Error();
    const stack = err.stack?.split('\n') || [];
    for (const line of stack) {
      // Find the start of the App Router app/ folder
      const appIndex = line.indexOf('.next/server/app/') !== -1 ? line.indexOf('.next/server/app/') + 17 : 
                       line.indexOf('.next\\server\\app\\') !== -1 ? line.indexOf('.next\\server\\app\\') + 17 :
                       line.indexOf('/app/') !== -1 ? line.indexOf('/app/') + 5 :
                       line.indexOf('\\app\\') !== -1 ? line.indexOf('\\app\\') + 5 : -1;
      
      if (appIndex !== -1) {
        const remainder = line.substring(appIndex);
        // Extracts everything up to page.tsx, route.ts, etc.
        const pageMatch = remainder.match(/^(.*?)[\\/]?(?:page|route)\.(?:js|ts|jsx|tsx)/i);
        if (pageMatch) {
          let route = '/' + pageMatch[1];
          // Convert Windows backslashes to URL forward slashes
          route = route.replace(/\\/g, '/');
          // Strip out Next.js Route Groups like /(dashboard)/users -> /users
          route = route.replace(/\/\([^/]+\)/g, '');
          // Clean up double slashes
          route = route.replace(/\/+/g, '/');
          return route === '' ? '/' : route;
        }
      }
    }
  } catch {
    /* Silently ignore on JS engines without Error.stack */
  }
  return null;
}

// ─── Deep Payload Sniffer (V2) ────────────────────────────────────────────────

/**
 * Decodes the `sub` claim from a compact JWT without signature verification.
 * Used to extract User IDs from Auth payloads so that the userId field 
 * is populated automatically.
 *
 * @param token - A compact JWT string in `header.payload.signature` format.
 * @returns The `sub` claim string, or `null` if the token cannot be decoded.
 *
 * @internal
 */
function extractUserIdFromJWT(token: string): string | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    // Validate signature shape to avoid parsing arbitrary dot-separated text
    if (!parts[0].startsWith('eyJ')) return null;

    // Convert base64url → standard base64, then pad to a multiple of 4.
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64.padEnd(b64.length + (4 - b64.length % 4) % 4, '=');
    const payload = JSON.parse(atob(padded)) as Record<string, unknown>;
    
    // Ignore anonymous / public keys; they do not represent a logged-in user
    if (payload.role === 'anon' || payload.role === 'public') return null;

    return typeof payload.sub === 'string' ? payload.sub : null;
  } catch {
    return null;
  }
}

/**
 * Deep recursive payload sniffer.
 * Iterates through completely unknown payloads (like complex chunked cookies,
 * Base64url-encoded strings, or nested objects) to forcefully extract the
 * authenticated User ID without relying on Framework-specific adapters.
 * * Supports decoding Supabase SSR's base64-encoded cookie payloads perfectly.
 *
 * @internal
 */
function findUserIdInPayload(payload: unknown, depth = 0): string | null {
  // Prevent infinite recursion on extremely deeply nested objects
  if (depth > 5 || payload === null || payload === undefined) return null;

  if (typeof payload === 'string') {
    let str = payload.trim();
    if (str.startsWith('base64-')) str = str.substring(7);
    
    // 1. Direct JWT Match
    if (str.startsWith('eyJ')) {
      const uid = extractUserIdFromJWT(str);
      if (uid) return uid;
    }

    // 2. URL Encoded Strings (Express / NextAuth format)
    try {
      const decoded = decodeURIComponent(str);
      if (decoded !== str) {
         let stripped = decoded;
         if (stripped.startsWith('base64-')) stripped = stripped.substring(7);
         if (stripped.startsWith('{') || stripped.startsWith('[')) {
           return findUserIdInPayload(JSON.parse(stripped), depth + 1);
         }
      }
    } catch {}

    // 3. Base64 / Base64Url Decoding (Supabase SSR format)
    try {
      const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
      const ascii = atob(b64 + pad);
      if (ascii.startsWith('{') || ascii.startsWith('[')) {
         return findUserIdInPayload(JSON.parse(ascii), depth + 1);
      }
    } catch {}

    return null;
  }
  
  if (typeof payload === 'object' && payload !== null) {
    const obj = payload as Record<string, unknown>;
    
    // Check known fast-paths first for optimization
    if (typeof obj.access_token === 'string') {
      const uid = extractUserIdFromJWT(obj.access_token);
      if (uid) return uid;
    }
    
    if (typeof obj.user_id === 'string' && !obj.user_id.startsWith('eyJ')) return obj.user_id;
    if (typeof obj.sub === 'string' && !obj.sub.startsWith('eyJ')) return obj.sub;
    
    // Deep recursive search for nested JWTs or IDs
    for (const key of Object.keys(obj)) {
      const result = findUserIdInPayload(obj[key], depth + 1);
      if (result) return result;
    }
  }
  return null;
}

/**
 * Safely extracts a Bearer token from the outgoing fetch arguments.
 * Allows capturing the JWT sent by external API requests or database REST queries.
 *
 * @internal
 */
function getAuthTokenFromFetchArgs(args: Parameters<typeof fetch>): string | null {
  let authHeader: string | null = null;
  const req = args[0];
  const init = args[1];

  if (typeof Request !== 'undefined' && req instanceof Request) {
    authHeader = req.headers.get('Authorization') ?? req.headers.get('authorization');
  } else if (init?.headers) {
    if (init.headers instanceof Headers) {
      authHeader = init.headers.get('Authorization') ?? init.headers.get('authorization');
    } else if (Array.isArray(init.headers)) {
      const pair = init.headers.find(h => h[0].toLowerCase() === 'authorization');
      authHeader = pair ? pair[1] : null;
    } else {
      const record = init.headers as Record<string, string>;
      authHeader = record['Authorization'] ?? record['authorization'] ?? record['AUTHORIZATION'] ?? null;
    }
  }

  if (authHeader?.toLowerCase().startsWith('bearer ')) {
    return authHeader.substring(7).trim();
  }
  return null;
}

/**
 * Attempts to read inbound request headers from Next.js `next/headers`.
 * Returns an empty object silently when the package is used outside Next.js
 * or when called outside a Server Component / Server Action context.
 *
 * @internal
 */
async function tryNextHeaders(): Promise<Partial<RequestContext>> {
  try {
    let mod: any = null;
    
    // 1. Turbopack Safe Import: Avoid dynamic string imports which fail strict static analysis
    try {
      if (typeof require !== 'undefined') {
        // @ts-ignore - Optional dependency, framework agnostic
        mod = require('next/headers');
      }
    } catch {}

    // 2. ESM Fallback
    if (!mod) {
      try {
        // @ts-ignore - Optional dependency, framework agnostic
        mod = await import('next/headers');
      } catch {}
    }

    if (!mod || !mod.headers) return {};

    // next/headers() is async in Next.js ≥ 15; synchronous in 14.
    const h = await Promise.resolve(mod.headers());

    // 1. Try internal routing headers or custom middleware headers
    let urlPath = h.get('x-current-path')
      ?? h.get('x-invoke-path') 
      ?? h.get('x-matched-path')
      ?? h.get('x-url')
      ?? h.get('x-pathname')
      ?? h.get('next-url');

    // Aggressively scan all headers just in case framework internals are changed
    if (!urlPath) {
      const headerEntries = typeof h.entries === 'function' ? (Array.from(h.entries()) as [string, unknown][]) : [];
      for (const [key, value] of headerEntries) {
        if (typeof key === 'string' && key.toLowerCase().includes('path') && typeof value === 'string' && value.startsWith('/')) {
          urlPath = value.split('?')[0];
          break;
        }
      }
    }

    // 2. Fallback to referer (present on form submissions and Server Actions)
    if (!urlPath) {
      const referer = h.get('referer');
      if (referer) {
        try { urlPath = new URL(referer).pathname; }
        catch { urlPath = referer.split('?')[0]; }
      }
    }

    // 3. Attempt to Sniff User ID from Incoming Headers/Cookies 
    let incomingUserId: string | null = null;
    const authHeader = h.get('authorization');
    if (authHeader?.toLowerCase().startsWith('bearer ')) {
      incomingUserId = extractUserIdFromJWT(authHeader.substring(7).trim());
    }

    if (!incomingUserId) {
      const cookieHeader = h.get('cookie');
      if (cookieHeader) {
        const chunkMap = new Map<string, Map<number, string>>();
        
        for (const pair of cookieHeader.split(';')) {
          const eqIdx = pair.indexOf('=');
          if (eqIdx === -1) continue;
          
          const rawName  = pair.slice(0, eqIdx).trim();
          let rawValue = pair.slice(eqIdx + 1).trim();

          // Strip Supabase URI encoding & base64 prefix if present in the raw string
          if (rawValue.startsWith('base64-')) rawValue = rawValue.substring(7);
          try { rawValue = decodeURIComponent(rawValue); } catch {}
          if (rawValue.startsWith('base64-')) rawValue = rawValue.substring(7);
          
          // Feed each standalone cookie value directly to the deep sniffer
          const standaloneUid = findUserIdInPayload(rawValue);
          if (standaloneUid) {
             incomingUserId = standaloneUid;
             break;
          }

          // Handle Chunked Cookies (e.g., Supabase SSR: sb-xyz-auth-token.0=...)
          const chunkMatch = rawName.match(/^(.+)\.(\d+)$/);
          if (chunkMatch) {
            const [, baseName, idxStr] = chunkMatch;
            if (!chunkMap.has(baseName)) chunkMap.set(baseName, new Map());
            chunkMap.get(baseName)!.set(Number(idxStr), rawValue);
          }
        }
        
        // If standalone cookies failed, attempt to reassemble and sniff chunks
        if (!incomingUserId) {
          for (const [, chunks] of chunkMap) {
            const assembled = [...chunks.entries()]
              .sort(([a], [b]) => a - b).map(([, v]) => v).join('');
            
            const chunkUid = findUserIdInPayload(assembled);
            if (chunkUid) {
              incomingUserId = chunkUid;
              break;
            }
          }
        }
      }
    }

    return {
      ipAddress: h.get('x-forwarded-for')?.split(',')[0].trim()
        ?? h.get('x-real-ip')
        ?? null,
      userAgent: h.get('user-agent') ?? null,
      httpMethod: h.get('x-http-method') ?? null,
      urlPath: urlPath ?? null,
      incomingUserId,
    };
  } catch {
    return {};
  }
}

/**
 * Constant User-Agent string substituted for the raw, misleading `'node'` UA
 * (or any Next.js-internal UA) reported during framework background
 * processes such as Static Generation, ISR revalidation, or `generateMetadata`
 * pre-rendering. See {@link resolveRequestContext}.
 */
const BACKGROUND_PROCESS_USER_AGENT = 'system:background-process';

/**
 * Sentinel value used for {@link AuditLogMetadata.userId} when an event was
 * produced by a framework background process rather than an unauthenticated
 * visitor. Distinguishes "we genuinely don't know who this is" (`null`, real
 * anonymous traffic) from "there is no visitor here at all" (`'SYSTEM'`,
 * build-time/ISR rendering).
 */
const SYSTEM_PROCESS_USER_ID = 'SYSTEM';

/**
 * Resolves the current {@link RequestContext} using the following fallback chain:
 *
 * 1. Explicitly set context via {@link captureRequestContext} (Node.js/Express).
 * 2. Auto-detected headers from Next.js `next/headers`.
 * 3. Magical V8 Stack Trace inference if Next.js stripped the headers.
 * 4. Client-side browser APIs (`window.location`, `navigator`) for Vue, React, Vanilla JS.
 * 5. Empty context — all fields are `null`.
 *
 * **Background process normalisation:** when the resolved `User-Agent` is the
 * bare string `'node'` or contains `'Next.js'` — both signatures of
 * server-internal rendering (Static Generation / ISR) rather than a real
 * inbound HTTP request — this function:
 * - Forces `urlPath` to the constant `'Background_Process'`, **overriding**
 * any stack-inferred app route. This keeps every event from the same
 * background render pass consistent (previously, sibling calls in the same
 * pass could resolve to different, misleading paths like `/api/profile`).
 * - Replaces the raw `'node'` / Next.js UA with {@link BACKGROUND_PROCESS_USER_AGENT}.
 * - Sets `incomingUserId` to {@link SYSTEM_PROCESS_USER_ID} when no real user
 * could be sniffed, so downstream `userId` is `'SYSTEM'` rather than `null`.
 *
 * @internal
 */
async function resolveRequestContext(): Promise<RequestContext> {
  const stored = requestContextStorage.getStore();
  if (stored) return stored;

  const next = await tryNextHeaders();
  let resolvedUrlPath = next.urlPath ?? null;

  // Magical Fallback: If framework violently stripped the URL headers, rip through the V8 Stack Trace!
  if (!resolvedUrlPath) {
    resolvedUrlPath = inferUrlPathFromStack();
  }

  // Detect Background Processes (Static Generation / ISR)
  // Explains why `ipAddress`, `userAgent`, and `userId` are naturally null in some logs
  const isBackgroundProcess = next.userAgent === 'node' || !!next.userAgent?.includes('Next.js');
  if (isBackgroundProcess) {
    // Override unconditionally — a stack-inferred path is misleading for
    // background renders and causes inconsistent urlPath values across
    // sibling calls within the same render pass.
    resolvedUrlPath = 'Background_Process';
  }

  // If headers succeeded in finding anything, use it
  if (next && (next.ipAddress || next.userAgent || resolvedUrlPath || next.incomingUserId)) {
    return {
      ipAddress: next.ipAddress ?? null,
      userAgent: isBackgroundProcess ? BACKGROUND_PROCESS_USER_AGENT : (next.userAgent ?? null),
      httpMethod: next.httpMethod ?? null,
      urlPath: resolvedUrlPath,
      incomingUserId: next.incomingUserId ?? (isBackgroundProcess ? SYSTEM_PROCESS_USER_ID : null),
    };
  }

  // Universal Browser Fallback (React, Vue, Vanilla JS, Laravel Blade client-side)
  if (typeof window !== 'undefined' && typeof window.location !== 'undefined') {
    return {
      ipAddress: null, // Cannot securely obtain IP purely client-side
      userAgent: window.navigator?.userAgent ?? null,
      httpMethod: 'CLIENT_ACTION',
      urlPath: window.location.pathname ?? null,
      incomingUserId: null,
    };
  }

  return {
    ipAddress: null,
    userAgent: null,
    httpMethod: null,
    urlPath: null,
    incomingUserId: null,
  };
}

/**
 * Attempts to extract a User ID from a cloned auth-endpoint response body.
 *
 * Handles common standard auth shapes:
 * - `{ id: string }`
 * - `{ user: { id: string } }`
 * - `{ access_token: string }` — JWT decoded to read the `sub` claim
 *
 * On any parse failure the function returns silently to avoid disrupting the
 * primary fetch response.
 *
 * @param response - A **cloned** Response whose body has not yet been consumed.
 * @param ctx      - The current {@link AuditContext} to update in-place.
 *
 * @internal
 */
async function tryExtractUserIdFromAuthResponse(
  response: Response,
  ctx: AuditContext,
): Promise<void> {
  try {
    const data = await response.json() as Record<string, unknown>;
    const uid = findUserIdInPayload(data);
    if (uid) ctx.capturedUserId = uid;
  } catch {
    /* Non-JSON or empty body — silently ignore. */
  }
}

/**
 * Generates a concise, human-readable one-line summary for an audit event.
 *
 * This summary is used verbatim as {@link AuditLogMetadata.message} for
 * `TRAINING` / `DEBUG` / `INFO` severities, and embedded as
 * {@link AuditMessageDetail.summary} for `WARN` / `ERROR` / `FATAL` /
 * `CRITICAL` severities (see {@link IntelligentAuditTrail.explainAnomaly}).
 *
 * @param resource     - Logical resource name (e.g. `'Article'`).
 * @param action       - CRUD operation performed.
 * @param status       - Operation outcome (`'SUCCESS'` or `'FAILURE'`).
 * @param duration     - Wall-clock duration in milliseconds.
 * @param severity     - Pre-computed severity of the event.
 * @param functionName - Optional name of the wrapping Function.
 * @returns A single descriptive string summarising the event.
 *
 * @internal
 */
function generateSummary(
  resource: string,
  action: AuditLogMetadata['action'],
  status: 'SUCCESS' | 'FAILURE',
  duration: number,
  severity: AuditSeverity,
  functionName?: string,
): string {
  const pastTense: Record<AuditLogMetadata['action'], string> = {
    CREATE: 'created', READ: 'read', UPDATE: 'updated',
    DELETE: 'deleted', UNKNOWN: 'accessed',
  };
  const verb = pastTense[action] ?? 'accessed';
  const via = functionName && functionName !== 'unknown' ? ` via ${functionName}` : '';

  switch (severity) {
    case 'TRAINING':
      return `[TRAINING] ${action} on ${resource}${via} recorded for baseline (${duration}ms)`;
    case 'DEBUG':
      return `[DEBUG] ${resource} ${verb}${via} in ${duration}ms`;
    case 'INFO':
      return `${resource} ${verb} successfully${via} in ${duration}ms`;
    case 'WARN':
      return status === 'SUCCESS' 
        ? `Abnormally slow/rare ${action} detected on ${resource}${via} (${duration}ms)` 
        : `Suspicious ${action} failed on ${resource}${via} after ${duration}ms`;
    case 'ERROR':
      return status === 'SUCCESS' 
        ? `Abnormally slow/rare ${action} detected on ${resource}${via} (${duration}ms)` 
        : `Failed to ${verb} ${resource}${via} after ${duration}ms`;
    case 'FATAL':
      return status === 'SUCCESS' 
        ? `Extreme anomaly (FATAL) on successful ${action} of ${resource}${via} (${duration}ms)` 
        : `Critical failure: ${action} on ${resource}${via} triggered an anomaly alert (${duration}ms)`;
    case 'CRITICAL':
      return status === 'SUCCESS' 
        ? `CRITICAL: Unprecedented successful ${action} on ${resource}${via} — immediate review required (${duration}ms)` 
        : `CRITICAL: Extreme anomaly on failed ${action} ${resource}${via} — immediate review required (${duration}ms)`;
  }
}

/**
 * Builds the final {@link AuditLogMetadata.message} value for an event.
 *
 * - `TRAINING` / `DEBUG` / `INFO` → plain string (the {@link generateSummary}
 * output), keeping the common case lightweight.
 * - `WARN` / `ERROR` / `FATAL` / `CRITICAL` → an {@link AuditMessageDetail}
 * object via {@link IntelligentAuditTrail.explainAnomaly}, embedding the
 * `summary` plus the duration/percentile/hour signals that justify the
 * severity.
 *
 * @internal
 */
function buildMessage(
  resource: string,
  action: AuditLogMetadata['action'],
  status: 'SUCCESS' | 'FAILURE',
  duration: number,
  severity: AuditSeverity,
  functionName?: string,
): string | AuditMessageDetail {
  const summary = generateSummary(resource, action, status, duration, severity, functionName);

  const isAnomalous = severity === 'WARN' || severity === 'ERROR'
    || severity === 'FATAL' || severity === 'CRITICAL';

  if (!isAnomalous) return summary;

  return auditTrail.explainAnomaly(resource, action, duration, summary);
}

// ─── Internal Error Detection ────────────────────────────────────────

/**
 * Returns `true` when the thrown value is an internal control-flow signal
 * (like Next.js `redirect()` or `notFound()`), which must never be treated as a
 * genuine application error and should be logged with `status: 'SUCCESS'`.
 *
 * @param error - The value caught in a `catch` block.
 * @returns `true` if the error originates from a framework redirect or 404.
 *
 * @internal
 */
function isFrameworkInternalThrow(error: unknown): boolean {
  if (error instanceof Error) {
    const digest = (error as { digest?: string }).digest;
    if (typeof digest === 'string') {
      return digest.startsWith('NEXT_REDIRECT') || digest.startsWith('NEXT_NOT_FOUND');
    }
    return error.message === 'NEXT_REDIRECT' || error.message === 'NEXT_NOT_FOUND';
  }
  return false;
}

// ─── Fetch Interceptor ────────────────────────────────────────────────────────

// Stop browser clients from intercepting and double-logging Next.js RSC fetches!
const isBrowserContext = typeof window !== 'undefined' && typeof window.document !== 'undefined';

if (!isBrowserContext && typeof globalThis !== 'undefined' && globalThis.fetch) {
  const originalFetch = globalThis.fetch;

  if (!(globalThis as Record<string, unknown>).__auditFetchPatched) {

    /**
     * Autonomous runtime fetch interceptor.
     *
     * Transparently wraps `globalThis.fetch` to detect outbound API calls
     * (REST, GraphQL, Supabase, Firebase, internal microservices) and 
     * — without manual instrumentation — infer:
     *
     * - **Resource**: derived from the URL path.
     * - **Action**: mapped from the HTTP method and URL pattern.
     * - **User ID**: extracted from auth responses, incoming cookies, or outgoing tokens.
     * - **Response status**: the HTTP status code returned by the endpoint.
     * - **Duration**: wall-clock time for the round-trip fetch.
     *
     * When called inside a {@link withAudit} context the interceptor only
     * records the action onto the shared {@link AuditContext}; the full log
     * entry is emitted once the wrapping function completes so that all
     * calls within one logical flow appear as a single audit record.
     */
    globalThis.fetch = async function (...args: Parameters<typeof fetch>): Promise<Response> {
      const auditCtx = networkQueryTracker.getStore();
      const isReqObj = typeof Request !== 'undefined' && args[0] instanceof Request;
      const requestUrl = (isReqObj ? (args[0] as Request).url : args[0]?.toString()) ?? '';
      const method = (isReqObj
        ? (args[0] as Request).method
        : (args[1] as RequestInit | undefined)?.method) ?? 'GET';
      const methodUpper = method.toUpperCase();

      let detectedAction: AuditLogMetadata['action'] | null = null;
      let detectedResource: string | null = null;
      let sniffedUserId: string | null = null;

      // Extract User ID from the outgoing Authorization header BEFORE executing request
      // This guarantees tracking for subsequent DB requests even when Auth API is not called
      const outgoingToken = getAuthTokenFromFetchArgs(args);
      if (outgoingToken) {
        sniffedUserId = extractUserIdFromJWT(outgoingToken);
        if (sniffedUserId && auditCtx && !auditCtx.capturedUserId) {
          auditCtx.capturedUserId = sniffedUserId;
        }
      }

      if (requestUrl.includes('/v1/')) {
        // ── Standard Database REST ─────────────────────────────────────────────
        if (requestUrl.includes('/rest/v1/') || requestUrl.includes('/api/v1/')) {
          try {
            const segments = new URL(requestUrl).pathname.split('/');
            const table = segments[segments.length - 1];

            // 🛑 CRITICAL FIX: RECURSION GUARD 🛑
            // Ignore outbound requests directed to the audit_logs table itself.
            if (table === 'audit_logs' || table === 'audit_log') {
              return originalFetch.apply(this, args);
            }

            if (table && table !== 'rpc') {
              detectedResource = table.charAt(0).toUpperCase() + table.slice(1);
              if (detectedResource.endsWith('s')) detectedResource = detectedResource.slice(0, -1);
            } else if (table === 'rpc') {
              detectedResource = 'RPC_Function';
            }
          } catch {
            detectedResource = 'Database';
          }
          if (requestUrl.includes('/rpc/')) {
            detectedAction = 'UPDATE';
          } else {
            if (methodUpper === 'GET') detectedAction = 'READ';
            if (methodUpper === 'POST') detectedAction = 'CREATE';
            if (methodUpper === 'PATCH' || methodUpper === 'PUT') detectedAction = 'UPDATE';
            if (methodUpper === 'DELETE') detectedAction = 'DELETE';
          }

          // ── Standard Auth APIs ────────────────────────────────────────────────
        } else if (requestUrl.includes('/auth/v1/') || requestUrl.includes('/identity/')) {
          detectedResource = 'Auth';
          if (requestUrl.includes('signup') || requestUrl.includes('register')) detectedAction = 'CREATE';
          else if (requestUrl.includes('token') || requestUrl.includes('user')) detectedAction = 'READ';
          else if (methodUpper === 'POST') detectedAction = 'CREATE';
          else if (methodUpper === 'PUT') detectedAction = 'UPDATE';
          else if (methodUpper === 'GET') detectedAction = 'READ';

          // ── Storage / Media APIs ──────────────────────────────────────────────
        } else if (requestUrl.includes('/storage/v1/') || requestUrl.includes('/media/')) {
          detectedResource = 'Storage';
          if (methodUpper === 'POST' || methodUpper === 'PUT') detectedAction = 'CREATE';
          if (methodUpper === 'DELETE') detectedAction = 'DELETE';
          if (methodUpper === 'GET') detectedAction = 'READ';
        }
      } else {
        // ── Generic REST / API Fallback (Laravel, Python, Express, Firebase) ────
        try {
          const parsedUrl = new URL(requestUrl, 'http://localhost');
          const segments = parsedUrl.pathname.split('/').filter(Boolean);

          // Ignore obvious static assets to prevent log spam
          if (!parsedUrl.pathname.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|map)$/i)) {
             let possibleResource = segments.length > 0 ? segments[segments.length - 1] : 'App';
             
             // If the last segment is an ID (numeric or UUID), take the parent segment as resource
             if (possibleResource.match(/^[\d-]+$/) || possibleResource.match(/^[0-9a-f]{8}-[0-9a-f]{4}/i)) {
               possibleResource = segments.length > 1 ? segments[segments.length - 2] : 'App';
             }

             detectedResource = possibleResource.charAt(0).toUpperCase() + possibleResource.slice(1);
             
             // Clarify microservice external hops to prevent developer confusion
             if (parsedUrl.port && parsedUrl.port !== '3000' && parsedUrl.port !== '80' && parsedUrl.port !== '443') {
                 detectedResource = `External_${detectedResource}`;
             }

             if (detectedResource.toLowerCase().includes('auth') || detectedResource.toLowerCase().includes('login')) {
               detectedResource = 'Auth';
             }

             if (methodUpper === 'GET') detectedAction = 'READ';
             else if (methodUpper === 'POST') detectedAction = 'CREATE';
             else if (methodUpper === 'PUT' || methodUpper === 'PATCH') detectedAction = 'UPDATE';
             else if (methodUpper === 'DELETE') detectedAction = 'DELETE';
             else detectedAction = 'UNKNOWN';
          }
        } catch {
          detectedResource = 'External_API';
          detectedAction = 'UNKNOWN';
        }
      }

      if (detectedAction) {
        // ── Inside a withAudit context ─────────────────────────────────────
          if (auditCtx) {
            auditCtx.actions.add(detectedAction);
            auditCtx.lastRequestUrl = requestUrl; // Store target for framework fallback
            auditCtx.lastHttpMethod = methodUpper;

            // Auto-capture userId from auth responses if sniffed header failed
            if (detectedResource === 'Auth' && !auditCtx.capturedUserId) {
              const result = await originalFetch.apply(this, args);
              await tryExtractUserIdFromAuthResponse(result.clone(), auditCtx);
              return result;
            }

            // ── Standalone fetch (no withAudit context) ────────────────────────
          } else {
            const startTime = Date.now();
            const result = await originalFetch.apply(this, args);
            const duration = Date.now() - startTime;
            const opStatus: 'SUCCESS' | 'FAILURE' = result.ok ? 'SUCCESS' : 'FAILURE';
            const finalResource = detectedResource ?? 'UnknownResource';
            const reqCtx = await resolveRequestContext();

            const { severity, anomalyScore } = await auditTrail.processEvent(
              finalResource, detectedAction, duration, opStatus,
            );
            
            const callerFunction = inferCallerFunctionName();
            const message = buildMessage(
              finalResource, detectedAction, opStatus, duration, severity, callerFunction,
            );

            // Try resolving user ID: Outgoing Header first, fallback to incoming cookies, then Auth response body
            let finalUserId: string | null = sniffedUserId || reqCtx.incomingUserId;
            if (detectedResource === 'Auth' && !finalUserId) {
              const tempCtx: AuditContext = {
                actions: new Set(), functionName: '', resource: '', capturedUserId: null,
              };
              await tryExtractUserIdFromAuthResponse(result.clone(), tempCtx);
              finalUserId = tempCtx.capturedUserId;
            }

            let endpointPath: string | null = null;
            try { endpointPath = new URL(requestUrl).pathname; } catch { endpointPath = requestUrl; }

            await emitAuditLog({
              resource: finalResource,
              functionName: callerFunction,
              action: detectedAction,
              userId: finalUserId,
              ipAddress: reqCtx.ipAddress,
              userAgent: reqCtx.userAgent,
              message,
              httpMethod: methodUpper || (['CREATE', 'UPDATE', 'DELETE'].includes(detectedAction) ? 'POST' : 'GET'),
              urlPath: reqCtx.urlPath ?? endpointPath, // Prioritise app route, fallback to API endpoint URL
              responseStatus: result.status,
              timestamp: new Date().toISOString(),
              duration,
              status: opStatus,
              severity,
              anomalyScore,
            });
            return result;
          }
        }

      return originalFetch.apply(this, args);
    };

    (globalThis as Record<string, unknown>).__auditFetchPatched = true;
  }
}

// ─── emitAuditLog ─────────────────────────────────────────────────────────────

/**
 * Sliding-window de-duplication cache for {@link emitAuditLog}.
 *
 * Maps a coarse `userId|baseResource|action` key (where `baseResource` strips
 * any `External_` prefix) to the timestamp of the most recent emission.
 *
 * **Why this exists:** a single logical operation often produces *two*
 * separate top-level audit entries — one for the app's own API route
 * (`Analyze`/`POST` at `/api/analyze`) and one for the outbound call that
 * route makes to a downstream microservice (`External_Analyze`/`POST` at the
 * same logical path) — because the downstream call happens outside any
 * {@link withAudit} context (the route handler wasn't wrapped in
 * {@link auditHandler}). Both entries describe the *same* user action a few
 * hundred milliseconds apart. This cache collapses that pair into a single
 * log line by suppressing the second emission.
 *
 * @internal
 */
const recentEmissions = new Map<string, number>();

/** Window (ms) within which a same-key emission is considered a duplicate. */
const DEDUPE_WINDOW_MS = 4000;

/**
 * Returns `true` if `payload` is a near-duplicate of another entry emitted
 * within {@link DEDUPE_WINDOW_MS}, and records this emission's timestamp for
 * future comparisons either way.
 *
 * Matching is intentionally coarse: same `userId` (or `null`/`'SYSTEM'`
 * bucket), same `action`, and the same resource name once any `External_`
 * prefix is stripped (so `Analyze` and `External_Analyze` collapse to the
 * same key). `TRAINING`-mode entries are also de-duplicated, since the
 * baseline file should not be polluted with the same nested-fetch pair
 * recorded twice.
 *
 * @internal
 */
function isDuplicateEmission(payload: AuditLogMetadata): boolean {
  const baseResource = payload.resource.replace(/^External_/, '');
  const userBucket = payload.userId ?? 'anon';
  const key = `${userBucket}|${baseResource}|${payload.action}`;

  const now = Date.now();
  const last = recentEmissions.get(key);
  recentEmissions.set(key, now);

  // Opportunistically prune old entries so the map doesn't grow unbounded.
  if (recentEmissions.size > 500) {
    for (const [k, ts] of recentEmissions) {
      if (now - ts > DEDUPE_WINDOW_MS) recentEmissions.delete(k);
    }
  }

  return last !== undefined && (now - last) < DEDUPE_WINDOW_MS;
}

/**
 * Writes a completed {@link AuditLogMetadata} entry to all configured output
 * channels and notifies every registered {@link AuditLogHandler}.
 *
 * **De-duplication:** before doing anything else, `payload` is checked
 * against {@link recentEmissions} via {@link isDuplicateEmission}. A
 * near-duplicate (same user, action, and resource-ignoring-`External_`-prefix
 * within {@link DEDUPE_WINDOW_MS}) is dropped silently — no console output,
 * no file write, no handler invocation — to avoid the same logical request
 * producing two top-level log lines (see {@link recentEmissions}).
 *
 * **Console routing by severity:**
 *
 * | Severity   | Method          | Prefix (ANSI)                  |
 * |------------|-----------------|--------------------------------|
 * | `DEBUG`    | `console.debug` | `[AUDIT:DEBUG]`                |
 * | `INFO`     | `console.info`  | `[AUDIT:INFO]`                 |
 * | `WARN`     | `console.warn`  | yellow `[AUDIT:WARN]`          |
 * | `ERROR`    | `console.error` | red `[AUDIT:ERROR]`            |
 * | `FATAL`    | `console.error` | magenta `[AUDIT:FATAL]`        |
 * | `CRITICAL` | `console.error` | white-on-red `[AUDIT:CRITICAL]`|
 * | `TRAINING` | `console.info`  | `[AUDIT:TRAINING]`             |
 *
 * **File routing:**
 * - `TRAINING` → `audit-baseline.jsonl`
 * - All others → `audit-production.jsonl`
 *
 * @param payload - Fully-populated audit log entry to emit.
 *
 * @internal
 */
async function emitAuditLog(payload: AuditLogMetadata): Promise<void> {
  if (isDuplicateEmission(payload)) return;

  const serialized = JSON.stringify(payload);

  switch (payload.severity) {
    case 'DEBUG':
      console.debug(`[AUDIT:DEBUG] ${serialized}`);
      break;
    case 'INFO':
      console.info(`[AUDIT:INFO] ${serialized}`);
      break;
    case 'WARN':
      console.warn(`\x1b[33m[AUDIT:WARN]\x1b[0m ${serialized}`);
      break;
    case 'ERROR':
      console.error(`\x1b[31m[AUDIT:ERROR]\x1b[0m ${serialized}`);
      break;
    case 'FATAL':
      console.error(`\x1b[35m[AUDIT:FATAL]\x1b[0m ${serialized}`);
      break;
    case 'CRITICAL':
      console.error(`\x1b[41m\x1b[37m[AUDIT:CRITICAL]\x1b[0m ${serialized}`);
      break;
    case 'TRAINING':
      console.info(`[AUDIT:TRAINING] ${serialized}`);
      break;
  }

  const targetFile = payload.severity === 'TRAINING'
    ? 'audit-baseline.jsonl'
    : 'audit-production.jsonl';

  try {
    if (typeof window === 'undefined') {
      const _global = globalThis as any;
      // Deno Native Fallback
      if (_global.Deno && _global.Deno.writeTextFileSync) {
        _global.Deno.writeTextFileSync(_global.Deno.cwd() + '/' + targetFile, serialized + '\n', { append: true });
      } else {
        // Node / Turbopack dynamic ESM loading
        const fs = await import('node:fs');
        const path = await import('node:path');
        fs.appendFileSync(path.join(process.cwd(), targetFile), serialized + '\n', 'utf8');
      }
    }
  } catch { /* File write failures are intentionally non-fatal. */ }

  for (const handler of auditTrail['_handlers']) {
    try { await handler(payload); }
    catch (err) { console.error('[Audit] onLog handler threw:', err); }
  }
}

// ─── IntelligentAuditTrail ────────────────────────────────────────────────────

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
export class IntelligentAuditTrail {
  private detector = new AuditAnomalyDetector();
  private mode: 'TRAINING' | 'PRODUCTION' = 'TRAINING';

  /**
   * @internal — accessed by {@link emitAuditLog} via string key to avoid
   * exposing the handler list in the public type surface.
   */
  _handlers: AuditLogHandler[] = [];

  // ─── Handler Registration ──────────────────────────────────────────────────

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
  onLog(handler: AuditLogHandler): this {
    this._handlers.push(handler);
    return this;
  }

  // ─── Mode Control ─────────────────────────────────────────────────────────

  /**
   * Sets the operating mode of the audit trail.
   *
   * Prefer {@link loadBaseline} over calling `setMode('PRODUCTION')` directly,
   * as `loadBaseline` also trains the Isolation Forest model before switching.
   *
   * @param mode - `'TRAINING'` to collect baseline data; `'PRODUCTION'` to
   * enable live anomaly detection.
   */
  setMode(mode: 'TRAINING' | 'PRODUCTION'): void {
    this.mode = mode;
    console.log(`\x1b[36m[Audit Trail]\x1b[0m Mode initialised as: ${mode}`);
  }

  // ─── Baseline Loading ─────────────────────────────────────────────────────

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
  async loadBaseline(source: AuditLogMetadata[] | string): Promise<void> {
    let baselineData: AuditLogMetadata[] = [];

    if (typeof source === 'string') {
      try {
        let fileContent = '';
        if (typeof window !== 'undefined') throw new Error('File system not available in browser');

        const _global = globalThis as any;
        // Deno Native Fast-Path
        if (_global.Deno && _global.Deno.readTextFileSync) {
           const filePath = source.startsWith('/') ? source : _global.Deno.cwd() + '/' + source;
           fileContent = _global.Deno.readTextFileSync(filePath);
        } else {
           // Node / Turbopack dynamic ESM fast-path
           const fs = await import('node:fs');
           const path = await import('node:path');
           const filePath = path.resolve(process.cwd(), source);
           fileContent = fs.readFileSync(filePath, 'utf8');
        }

        baselineData = fileContent
          .split('\n')
          .filter((line: string) => line.trim().length > 0)
          .map((line: string) => JSON.parse(line) as AuditLogMetadata);
      } catch (err) {
        console.error('\x1b[31m[Audit ML] Failed to load baseline file:\x1b[0m', err instanceof Error ? err.message : err);
        return;
      }
    } else if (Array.isArray(source)) {
      baselineData = source;
    } else {
      console.error('\x1b[31m[Audit ML] Invalid baseline format.\x1b[0m');
      return;
    }

    this.detector.loadPresetBaseline(baselineData);
    this.mode = 'PRODUCTION';
  }

  // ─── Severity Computation ─────────────────────────────────────────────────

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
  private computeSeverity(
    score: number,
    isSuspicious: boolean,
    status: 'SUCCESS' | 'FAILURE',
  ): AuditSeverity {
    const t = this.detector.threshold;

    if (status === 'FAILURE') {
      if (score > t + 0.20) return 'CRITICAL';
      if (score > t + 0.10) return 'FATAL';
      return 'ERROR';
    }

    // SUCCESS path
    if (!isSuspicious) {
      return score <= 0.30 ? 'DEBUG' : 'INFO';
    }

    // Suspicious + SUCCESS
    if (score > t + 0.20) return 'CRITICAL';
    if (score > t + 0.10) return 'FATAL';
    if (score > t + 0.05) return 'ERROR';
    return 'WARN';
  }

  // ─── Event Processing ─────────────────────────────────────────────────────

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
  async processEvent(
    resource: string,
    action: AuditLogMetadata['action'],
    duration: number,
    status: 'SUCCESS' | 'FAILURE' = 'SUCCESS',
  ): Promise<{ severity: AuditSeverity; anomalyScore: number }> {
    if (this.mode === 'TRAINING') {
      return { severity: 'TRAINING', anomalyScore: 0 };
    }
    try {
      const { score, isSuspicious } = this.detector.analyzeActivity(resource, action, duration);
      return {
        severity: this.computeSeverity(score, isSuspicious, status),
        anomalyScore: parseFloat(score.toFixed(4)),
      };
    } catch {
      return { severity: 'TRAINING', anomalyScore: 0 };
    }
  }

  // ─── Explainability ───────────────────────────────────────────────────────

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
  explainAnomaly(
    resource: string,
    action: AuditLogMetadata['action'],
    duration: number,
    summary: string,
  ): AuditMessageDetail {
    const hour = new Date().getHours();
    const stats = this.detector.getDurationStats(resource, action);

    const detail: AuditMessageDetail = {
      summary,
      duration_ms: duration,
      hour,
    };

    if (stats.sampleCount === 0) {
      detail.reason = `No baseline for ${resource}/${action} — anomaly based on novelty`;
      return detail;
    }

    detail.p99_duration_ms = stats.p99;
    if (stats.typicalHours.length > 0) {
      detail.typical_hours = stats.typicalHours;
    }

    if (stats.p99 > 0) {
      const deviationPct = Math.round(((duration - stats.p99) / stats.p99) * 100);
      detail.deviation = `${deviationPct >= 0 ? '+' : ''}${deviationPct}%`;
    }

    const reasonParts: string[] = [];
    if (stats.p99 > 0 && duration > stats.p99) {
      reasonParts.push(`duration ${duration}ms > p99 threshold ${stats.p99}ms for ${resource}/${action}`);
    }
    if (stats.typicalHours.length > 0 && !stats.typicalHours.includes(hour)) {
      reasonParts.push(`hour ${hour} is outside typical hours [${stats.typicalHours.join(',')}] for ${resource}/${action}`);
    }
    if (reasonParts.length > 0) {
      detail.reason = reasonParts.join('. ');
    }

    return detail;
  }
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
export const auditTrail = new IntelligentAuditTrail();

// ─── captureRequestContext ────────────────────────────────────────────────────

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
export async function captureRequestContext<T>(
  request: {
    headers: { get(key: string): string | null | undefined };
    method?: string;
    url?: string;
  },
  fn: () => Promise<T>,
): Promise<T> {
  const rawIp = request.headers.get('x-forwarded-for')
    ?? request.headers.get('x-real-ip')
    ?? null;

  let urlPath: string | null = null;
  if (request.url) {
    try { urlPath = new URL(request.url).pathname; }
    catch { urlPath = request.url; }
  }

  // Attempt to resolve userId from the inbound request so that handlers
  // wrapped with auditHandler() or captureRequestContext() get userId populated
  // automatically without a separate Supabase/Firebase auth call.
  let incomingUserId: string | null = null;

  const authHeader = request.headers.get('authorization') ?? request.headers.get('Authorization');
  if (authHeader?.toLowerCase().startsWith('bearer ')) {
    incomingUserId = extractUserIdFromJWT(authHeader.substring(7).trim());
  }

  if (!incomingUserId) {
    const cookieHeader = request.headers.get('cookie') ?? request.headers.get('Cookie') ?? '';
    if (cookieHeader) {
      // Direct JWT scan
      const jwtMatches = cookieHeader.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g);
      if (jwtMatches) {
        for (const jwt of jwtMatches) {
          const uid = extractUserIdFromJWT(jwt);
          if (uid) { incomingUserId = uid; break; }
        }
      }
      
      // Deep Payload Sniffer for Chunked or Base64 Encoded Cookies 
      // (Supports complex SSR implementations like Supabase, Firebase, and NextAuth)
      if (!incomingUserId) {
        const chunkMap = new Map<string, Map<number, string>>();
        for (const pair of cookieHeader.split(';')) {
          const eqIdx = pair.indexOf('=');
          if (eqIdx === -1) continue;
          
          const rawName  = pair.slice(0, eqIdx).trim();
          let rawValue = pair.slice(eqIdx + 1).trim();

          // Strip Supabase URI encoding & base64 prefix if present in the raw string
          if (rawValue.startsWith('base64-')) rawValue = rawValue.substring(7);
          try { rawValue = decodeURIComponent(rawValue); } catch {}
          if (rawValue.startsWith('base64-')) rawValue = rawValue.substring(7);
          
          // Attempt deep extraction on standalone chunks
          const standaloneUid = findUserIdInPayload(rawValue);
          if (standaloneUid) { incomingUserId = standaloneUid; break; }

          const chunkMatch = rawName.match(/^(.+)\.(\d+)$/);
          if (!chunkMatch) continue;
          const [, baseName, idxStr] = chunkMatch;
          if (!chunkMap.has(baseName)) chunkMap.set(baseName, new Map());
          chunkMap.get(baseName)!.set(Number(idxStr), rawValue);
        }
        
        // Reassemble and sniff if standalone evaluation failed
        if (!incomingUserId) {
          for (const [, chunks] of chunkMap) {
            const assembled = [...chunks.entries()]
              .sort(([a], [b]) => a - b).map(([, v]) => v).join('');
            
            const chunkUid = findUserIdInPayload(assembled);
            if (chunkUid) { incomingUserId = chunkUid; break; }
          }
        }
      }
    }
  }

  const ctx: RequestContext = {
    ipAddress: rawIp ? rawIp.split(',')[0].trim() : null,
    userAgent: request.headers.get('user-agent') ?? null,
    httpMethod: request.method ?? null,
    urlPath,
    incomingUserId,
  };
  return requestContextStorage.run(ctx, fn);
}

// ─── setCurrentPath ──────────────────────────────────────────────────────────

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
export function setCurrentPath(path: string): void {
  const existing = requestContextStorage.getStore();
  requestContextStorage.enterWith({
    ipAddress:      existing?.ipAddress      ?? null,
    userAgent:      existing?.userAgent      ?? null,
    httpMethod:     existing?.httpMethod     ?? null,
    incomingUserId: existing?.incomingUserId ?? null,
    urlPath: path,
  });
}

// ─── UNIFIED AUDIT CORE ───────────────────────────────────────────────────────

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
export function audit<T extends unknown[], R>(
  targetFunc: (...args: T) => Promise<R>,
  options?: { resource?: string; functionName?: string; urlPath?: string; action?: AuditLogMetadata['action'] },
): (...args: T) => Promise<R> {
  const initFallbackUrl = inferUrlPathFromStack();
  const rawName = targetFunc.name || 'unknown';

  // Intelligently map standard REST function names to Actions if omitted
  let inferredAction = options?.action;
  if (!inferredAction) {
     const upper = rawName.toUpperCase();
     if (upper.includes('POST') || upper.includes('CREATE')) inferredAction = 'CREATE';
     else if (upper.includes('GET') || upper.includes('READ')) inferredAction = 'READ';
     else if (upper.includes('PUT') || upper.includes('PATCH') || upper.includes('UPDATE')) inferredAction = 'UPDATE';
     else if (upper.includes('DELETE')) inferredAction = 'DELETE';
  }

  // Intelligently extract the Resource name by stripping CRUD verbs
  const resolvedName = options?.functionName ?? rawName;
  const inferredResource = resolvedName.replace(/^(get|create|update|delete|post|put|patch)/i, '') || 'App';
  const resolvedResource = options?.resource ?? inferredResource;

  return async (...args: T): Promise<R> => {
    // 1. Detect if this is an API Route receiving a Web Request
    const firstArg = args[0] as Record<string, unknown> | null | undefined;
    const isWebRequest = (
      firstArg instanceof Request                                   
      || firstArg?.['request'] instanceof Request                   
      || (firstArg?.['req'] && typeof (firstArg['req'] as any)['url'] === 'string')
    );

    // 2. Core Execution Engine
    const executeWithAudit = async () => {
      const ctx: AuditContext = {
        actions: new Set(),
        functionName: resolvedName,
        resource: resolvedResource,
        capturedUserId: null,
        overrideUrlPath: options?.urlPath,
      };
      const startTime = Date.now();

      const emit = async (
        status: 'SUCCESS' | 'FAILURE',
        actionsOverride?: AuditLogMetadata['action'][],
        errorDetails?: Record<string, unknown>,
        responseStatus?: number,
      ) => {
        const duration = Date.now() - startTime;
        const reqCtx = await resolveRequestContext();
        
        const toEmit = actionsOverride
          ?? (inferredAction ? [inferredAction] : (ctx.actions.size > 0 ? [...ctx.actions] : ['READ' as const]));

        // Merge manually recorded field diffs
        const extra: Partial<AuditLogMetadata> = {};
        if (ctx.capturedFieldChanges?.length) {
          const change = ctx.capturedFieldChanges[0];
          extra.tableName = change.tableName;
          extra.fieldName = change.fieldName;
          extra.recordId = change.recordId;
          extra.oldValue = change.oldValue;
          extra.newValue = change.newValue;
        }
        if (ctx.capturedPayload !== undefined) {
          extra.payload = ctx.capturedPayload;
        }

        for (const action of toEmit) {
          const { severity, anomalyScore } = await auditTrail.processEvent(
            resolvedResource, action, duration, status,
          );
          const message = buildMessage(
            resolvedResource, action, status, duration, severity, ctx.functionName,
          );
          
          let endpointPath: string | null = null;
          if (ctx.lastRequestUrl) {
            try { endpointPath = new URL(ctx.lastRequestUrl).pathname; }
            catch { endpointPath = ctx.lastRequestUrl; }
          }

          const isInternalEndpoint = endpointPath
            ? /\/(rest|auth|storage|graphql|firestore|identity)\/v\d+\//.test(endpointPath)
              || /^\/api\/v\d+\//.test(endpointPath)
            : false;
          const resolvedUrlPath = ctx.overrideUrlPath
            ?? reqCtx.urlPath
            ?? initFallbackUrl
            ?? (isInternalEndpoint ? null : endpointPath);
            
          let resolvedHttpMethod = reqCtx.httpMethod 
            ?? ctx.lastHttpMethod 
            ?? (['CREATE', 'UPDATE', 'DELETE'].includes(action) ? 'POST' : 'GET');
            
          // Force POST for Server Action mutations if the framework leaked a 'GET' from the parent page
          if (resolvedHttpMethod === 'GET' && ['CREATE', 'UPDATE', 'DELETE'].includes(action)) {
             resolvedHttpMethod = 'POST';
          }

          await emitAuditLog({
            resource: resolvedResource,
            functionName: ctx.functionName,
            action,
            userId: ctx.capturedUserId || reqCtx.incomingUserId,
            ipAddress: reqCtx.ipAddress,
            userAgent: reqCtx.userAgent,
            message,
            httpMethod: resolvedHttpMethod,
            urlPath: resolvedUrlPath,
            timestamp: new Date().toISOString(),
            duration,
            status,
            severity,
            anomalyScore,
            responseStatus, // ✅ Forcefully injected for ALL calls!
            ...extra,
            ...(errorDetails ? { details: errorDetails } : {}),
          });
        }
      };

      try {
        const result = await networkQueryTracker.run(ctx, () => targetFunc(...args));
        
        // Determine HTTP Status Code for the successful response
        let resStatus = 200; // Default HTTP 200 for Server Actions
        if (result && typeof result === 'object' && 'status' in result && typeof (result as any).status === 'number') {
          resStatus = (result as any).status;
        }

        await emit('SUCCESS', undefined, undefined, resStatus);
        return result;
      } catch (error) {
        if (isFrameworkInternalThrow(error)) {
          await emit('SUCCESS', undefined, undefined, 303); // Next.js redirects are always HTTP 303
          throw error;
        }

        const failureActions = ctx.actions.size > 0
          ? [...ctx.actions]
          : (['UNKNOWN'] as AuditLogMetadata['action'][]);

        await emit(
          'FAILURE',
          failureActions,
          { error: error instanceof Error ? error.message : 'Unknown error' },
          500 // Unhandled errors throw HTTP 500
        );
        throw error;
      }
    };

    // 3. Routing Engine (If it's an API Route, wrap it in RequestContext)
    if (isWebRequest && firstArg && 'headers' in firstArg) {
      return captureRequestContext(
        firstArg as any,
        executeWithAudit
      );
    }

    return executeWithAudit();
  };
}

// ─── Legacy Aliases (Prevents Breaking Changes) ─────────────────────────────
export const auditHandler = audit;
export const auditServerAction = audit;

/**
 * Zero‑boilerplate audit wrapper specifically designed for **React Server Components (Pages)**.
 *
 * In Next.js App Router, a Server Component (page) is an async function that runs on the server
 * during the request. It may call Server Actions, fetch data, or invoke utility functions.
 * `auditPage` wraps the default export of a `page.tsx` file so that:
 *
 * - The **page render itself** is treated as a `READ` operation on the provided `resource`.
 * - All **downstream Server Actions** called during the render automatically inherit the
 *   correct `urlPath`, `ipAddress`, `userAgent`, and `userId` without extra configuration.
 * - The `urlPath` is resolved from the actual route (e.g. `/dashboard`, `/blog/[slug]`),
 *   using Next.js internal headers and stack trace inference.
 * - Background processes (ISR, static generation) are detected and logged with
 *   `userId = 'SYSTEM'` and `userAgent = 'system:background-process'`.
 *
 * ### Why not just use `audit` on a page?
 * - `audit` expects an async function that may receive a `Request` object. A Server Component
 *   does **not** receive a request object – it receives `params` and `searchParams` only.
 * - `auditPage` manually extracts the request context from Next.js internal headers
 *   (`next/headers`, stack traces) and attaches it to `AsyncLocalStorage` so that every
 *   child operation (Server Actions, fetches, etc.) sees the correct request context.
 * - It also forces the `action` to `'READ'` (or an overridden value) because rendering a page
 *   is semantically a read operation.
 *
 * ### What is automatically captured in the audit log when you wrap a page:
 * - `resource` – logical name you provide (e.g. `'Dashboard'`, `'ArticlePage'`).
 * - `action` – `'READ'` by default (can be overridden).
 * - `functionName` – the original Server Component function name, or `'Page_Render'` fallback.
 * - `urlPath` – the actual route path (e.g. `/dashboard`, `/blog/hello-world`).
 * - `ipAddress`, `userAgent`, `userId` – extracted from the incoming request (or normalised
 *   for background processes).
 * - `duration` – total wall‑clock time from page entry until the returned JSX is resolved.
 * - `status` – `'SUCCESS'` if the page renders without throwing; `'FAILURE'` if an error
 *   is thrown (and then re‑thrown for Next.js to handle).
 * - `severity` / `anomalyScore` – computed by the ML model based on duration, hour, and
 *   resource/action novelty.
 *
 * ### When to use:
 * - Every `page.tsx` that represents a user‑visible route and where you want to track
 *   “a user viewed this page” as an audit event.
 * - Pages that call Server Actions – wrapping the page guarantees those actions inherit
 *   the correct request metadata (especially `urlPath`, which is otherwise lost).
 *
 * ### When not to use:
 * - API routes (`route.ts`) – use {@link audit} or {@link auditHandler} instead.
 * - Server Actions directly (`'use server'` functions) – use {@link audit} (or
 *   `auditServerAction` alias) instead.
 * - Client components – this wrapper runs on the server only.
 *
 * @param pageComponent - The async React Server Component function (the default export of a page file).
 * @param options - Configuration (all optional).
 * @param options.resource - Logical resource name for the page. If omitted, the function name
 *   with `'Page'` stripped is used (e.g. `DashboardPage` → `'Dashboard'`).
 * @param options.functionName - Explicit display name for the audit log. Defaults to the
 *   component's `name` property or `'Page_Render'`.
 * @param options.urlPath - Hard‑coded URL path override (e.g. when the real route is dynamic
 *   and stack inference fails). Takes precedence over auto‑detected path.
 * @param options.action - Override the action type (default `'READ'`). You rarely need to change this.
 *
 * @returns A wrapped async function with the exact same signature as the original page component.
 *
 * @note **Important:** `auditPage` only captures the page render itself.  
 * To have **Server Actions called from this page** also record the correct `urlPath`,
 * you **must** also call {@link setCurrentPath} in your Next.js middleware (or equivalent).  
 * This is because Server Actions run in a separate HTTP request that does not automatically
 * inherit the page’s route path. The middleware sets the path into the async context for
 * every incoming request, including Server Action requests.
 *
 * @example
 * ```tsx
 * // app/dashboard/page.tsx
 * import { auditPage } from 'intelligent-audit-trail';
 *
 * async function DashboardPage() {
 *   const user = await getUser();
 *   const articles = await getArticles();
 *   return <DashboardClient user={user} articles={articles} />;
 * }
 *
 * export default auditPage(DashboardPage, { resource: 'Dashboard' });
 * ```
 *
 * @example
 * ```tsx
 * // app/blog/[slug]/page.tsx (dynamic route)
 * import { auditPage } from 'intelligent-audit-trail';
 *
 * async function BlogPostPage({ params }: { params: { slug: string } }) {
 *   const post = await getPost(params.slug);
 *   return <article>{post.content}</article>;
 * }
 *
 * export default auditPage(BlogPostPage, { resource: 'BlogPost' });
 * ```
 *
 * @example
 * ```tsx
 * // Overriding the URL path if auto‑detection fails (rare)
 * export default auditPage(MyPage, {
 *   resource: 'MyCustomResource',
 *   urlPath: '/custom/path',
 * });
 * ```
 *
 * @example
 * ```ts
 * // Required middleware to propagate path to Server Actions (Next.js)
 * // middleware.ts
 * import { NextResponse, type NextRequest } from 'next/server';
 * import { setCurrentPath } from 'intelligent-audit-trail';
 *
 * export function middleware(request: NextRequest) {
 *   setCurrentPath(request.nextUrl.pathname);
 *   return NextResponse.next();
 * }
 * ```
 */
export function auditPage<T extends (...args: any[]) => any>(
  pageComponent: T,
  options?: { resource?: string; functionName?: string; urlPath?: string; action?: AuditLogMetadata['action'] }
): T {
  const initFallbackUrl = inferUrlPathFromStack();
  const resolvedName = options?.functionName ?? pageComponent.name ?? 'Page_Render';
  const inferredResource = resolvedName.replace(/Page$/i, '') || 'Page';
  const resolvedResource = options?.resource ?? inferredResource;

  const audited = audit(
    pageComponent as (...args: any[]) => Promise<any>, 
    { ...options, resource: resolvedResource, functionName: resolvedName, action: options?.action ?? 'READ' }
  );

  return (async (...args: any[]) => {
    const reqCtx = await tryNextHeaders();
    const fallbackUrl = initFallbackUrl ?? inferUrlPathFromStack();
    const finalUrl = options?.urlPath ?? reqCtx.urlPath ?? fallbackUrl;
    
    const ctx: RequestContext = {
      ipAddress: reqCtx.ipAddress ?? null,
      userAgent: reqCtx.userAgent ?? null,
      httpMethod: reqCtx.httpMethod ?? 'GET',
      urlPath: finalUrl,
      incomingUserId: reqCtx.incomingUserId ?? null,
    };

    return requestContextStorage.run(ctx, () => audited(...args));
  }) as unknown as T;
}

// ─── trackActions ─────────────────────────────────────────────────────────────

/**
 * Wraps every method of a plain service object with the unified `audit` wrapper.
 */
export function trackActions<T extends Record<string, unknown>>(
  actions: T,
  resourceName: string,
): T {
  const wrappedCache = new Map<string | symbol, unknown>();

  return new Proxy(actions, {
    get(target, propKey, receiver) {
      if (wrappedCache.has(propKey)) return wrappedCache.get(propKey);

      const originalValue = Reflect.get(target, propKey, receiver);
      if (typeof originalValue !== 'function') return originalValue;

      const funcName = (originalValue as { name?: string }).name || propKey.toString();
      const wrapped = audit(originalValue as (...a: unknown[]) => Promise<unknown>, {
        resource: resourceName,
        functionName: funcName,
      });

      const SKIP = new Set(['length', 'name', 'prototype', 'caller', 'arguments']);
      for (const key of Reflect.ownKeys(originalValue as object)) {
        if (SKIP.has(key as string)) continue;
        try { Reflect.set(wrapped, key, Reflect.get(originalValue as object, key)); }
        catch { /* non-writable or non-configurable — skip silently */ }
      }

      wrappedCache.set(propKey, wrapped);
      return wrapped;
    },
  });
}

// ─── Generic Database CDC Webhook ─────────────────────────────────────────────

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
export const auditWebhookReceiver = audit(
  async function auditWebhookReceiver(request: Request) {
    try {
      const payload = await request.json();
      
      // Auto-map aliases from different DB webhooks (Postgres, Supabase, MySQL CDC)
      const tableName = payload.tableName || payload.table;
      const operation = payload.operation || payload.event || payload.type;
      const oldRecord = payload.oldRecord || payload.oldData || payload.old_record || payload.old;
      const newRecord = payload.newRecord || payload.newData || payload.record || payload.new;
      
      const opUpper = operation?.toUpperCase();
      
      // Attempt to capture the row's primary key (id, uuid, etc)
      const recordId = newRecord?.id || oldRecord?.id || newRecord?.uuid || oldRecord?.uuid;
      
      if (tableName) {
        if ((opUpper === 'UPDATE' || opUpper === 'PATCH') && oldRecord && newRecord) {
          for (const key of Object.keys(newRecord)) {
            if (JSON.stringify(oldRecord[key]) !== JSON.stringify(newRecord[key])) {
               recordFieldChange(tableName, key, oldRecord[key], newRecord[key], recordId);
            }
          }
        } else if ((opUpper === 'INSERT' || opUpper === 'CREATE') && newRecord) {
          for (const key of Object.keys(newRecord)) {
             recordFieldChange(tableName, key, null, newRecord[key], recordId);
          }
        } else if (opUpper === 'DELETE' && oldRecord) {
          for (const key of Object.keys(oldRecord)) {
             recordFieldChange(tableName, key, oldRecord[key], null, recordId);
          }
        }
      }
      
      return new Response(JSON.stringify({ success: true, message: "CDC processed" }), { 
        status: 200, 
        headers: { 'Content-Type': 'application/json' } 
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: "Invalid generic CDC payload" }), { status: 400 });
    }
  },
  { resource: 'Database_CDC' }
);