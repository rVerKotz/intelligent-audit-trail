import fs from 'fs';
import path from 'path';
import { AsyncLocalStorage } from 'async_hooks';
import { AuditAnomalyDetector } from '../models/isolation-forest';

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
export interface AuditLogMetadata {
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
export type AuditLogHandler = (payload: AuditLogMetadata) => void | Promise<void>;

/**
 * Audit context carried through {@link AsyncLocalStorage}.
 *
 * @internal
 */
interface AuditContext {
  actions: Set<AuditLogMetadata['action']>;
  functionName: string;
  resource: string;
}

/**
 * AsyncLocalStorage instance used to propagate {@link AuditContext} across
 * asynchronous boundaries within a single Server Action invocation.
 *
 * @internal
 */
const networkQueryTracker = new AsyncLocalStorage<AuditContext>();

// ─── Next.js redirect / notFound sentinel detection ──────────────────────────

/**
 * Returns `true` when the thrown value is a Next.js internal control-flow
 * signal (`redirect()` or `notFound()`), which should never be treated as a
 * genuine application error.
 *
 * @param error - The value caught in a `catch` block.
 * @returns `true` if the error is a Next.js redirect or not-found signal.
 *
 * @internal
 */
function isNextInternalThrow(error: unknown): boolean {
  if (error instanceof Error) {
    const digest = (error as any).digest as string | undefined;
    if (typeof digest === 'string') {
      return digest.startsWith('NEXT_REDIRECT') || digest.startsWith('NEXT_NOT_FOUND');
    }
    return error.message === 'NEXT_REDIRECT' || error.message === 'NEXT_NOT_FOUND';
  }
  return false;
}

// ─── Autonomous Runtime Fetch Interceptor ────────────────────────────────────

if (typeof globalThis !== 'undefined' && globalThis.fetch) {
  const originalFetch = globalThis.fetch;

  if (!(globalThis as any).__auditFetchPatched) {
    globalThis.fetch = async function (...args) {
      const ctx = networkQueryTracker.getStore();

      const isReqObj = typeof Request !== 'undefined' && args[0] instanceof Request;
      const requestUrl = (isReqObj ? (args[0] as Request).url : args[0]?.toString()) || '';
      const method = (isReqObj ? (args[0] as Request).method : (args[1] as RequestInit)?.method) || 'GET';
      const methodUpper = method.toUpperCase();

      let detectedAction: AuditLogMetadata['action'] | null = null;
      let detectedResource: string | null = null;

      if (requestUrl.includes('/v1/')) {
        if (requestUrl.includes('/rest/v1/')) {
          try {
            const urlObj = new URL(requestUrl);
            const pathSegments = urlObj.pathname.split('/');
            const tableName = pathSegments[pathSegments.length - 1];

            if (tableName && tableName !== 'rpc') {
              detectedResource = tableName.charAt(0).toUpperCase() + tableName.slice(1);
              if (detectedResource.endsWith('s')) detectedResource = detectedResource.slice(0, -1);
            } else if (tableName === 'rpc') {
              detectedResource = 'RPC_Function';
            }
          } catch (_) {
            detectedResource = 'Database';
          }

          if (requestUrl.includes('/rpc/')) {
            detectedAction = 'UPDATE';
          } else {
            if (methodUpper === 'GET')                            detectedAction = 'READ';
            if (methodUpper === 'POST')                           detectedAction = 'CREATE';
            if (methodUpper === 'PATCH' || methodUpper === 'PUT') detectedAction = 'UPDATE';
            if (methodUpper === 'DELETE')                         detectedAction = 'DELETE';
          }
        } else if (requestUrl.includes('/auth/v1/')) {
          detectedResource = 'Auth';
          if (requestUrl.includes('signup'))                                    detectedAction = 'CREATE';
          else if (requestUrl.includes('token') || requestUrl.includes('user')) detectedAction = 'READ';
          else if (methodUpper === 'POST')  detectedAction = 'CREATE';
          else if (methodUpper === 'PUT')   detectedAction = 'UPDATE';
          else if (methodUpper === 'GET')   detectedAction = 'READ';
        } else if (requestUrl.includes('/storage/v1/')) {
          detectedResource = 'Storage';
          if (methodUpper === 'POST' || methodUpper === 'PUT') detectedAction = 'CREATE';
          if (methodUpper === 'DELETE')                        detectedAction = 'DELETE';
          if (methodUpper === 'GET')                           detectedAction = 'READ';
        }

        if (detectedAction) {
          if (ctx) {
            ctx.actions.add(detectedAction);
          } else {
            const startTime = Date.now();
            const result = await originalFetch.apply(this, args);
            const duration = Date.now() - startTime;

            const finalResource = detectedResource || 'UnknownResource';
            const { severity, anomalyScore } = await auditTrail.processEvent(
              finalResource, detectedAction, duration
            );

            await emitAuditLog({
              resource: finalResource,
              functionName: 'Direct_Client_Action',
              action: detectedAction,
              timestamp: new Date().toISOString(),
              duration,
              status: result.ok ? 'SUCCESS' : 'FAILURE',
              severity: severity as AuditLogMetadata['severity'],
              anomalyScore,
            });

            return result;
          }
        }
      }

      return originalFetch.apply(this, args);
    };

    (globalThis as any).__auditFetchPatched = true;
  }
}

// ─── Shared log emitter ───────────────────────────────────────────────────────

/**
 * Writes a completed {@link AuditLogMetadata} entry to the appropriate output
 * channels based on its severity level, then forwards it to every registered
 * {@link AuditLogHandler}.
 *
 * File routing:
 * - `TRAINING`   → console.info  + `audit-baseline.jsonl`
 * - `NORMAL`     → console.log   + `audit-production.jsonl`
 * - `SUSPICIOUS` → console.warn  + `audit-production.jsonl`
 *
 * @param payload - The fully-populated audit log entry to emit.
 *
 * @internal
 */
async function emitAuditLog(payload: AuditLogMetadata): Promise<void> {
  // ── Console output ──────────────────────────────────────────────────────────
  if (payload.severity === 'SUSPICIOUS') {
    console.warn(`\x1b[33m[AUDIT ALERT]\x1b[0m ${JSON.stringify(payload)}`);
  } else if (payload.severity === 'TRAINING') {
    console.info(`[AUDIT TRAINING LOG] ${JSON.stringify(payload)}`);
  } else {
    console.log(`[Audit Captured] ${JSON.stringify(payload)}`);
  }

  // ── File persistence ────────────────────────────────────────────────────────
  // TRAINING → baseline file used to later call loadBaseline()
  // NORMAL / SUSPICIOUS → production audit log for review and DB import
  const targetFile = payload.severity === 'TRAINING'
    ? 'audit-baseline.jsonl'
    : 'audit-production.jsonl';

  try {
    fs.appendFileSync(
      path.join(process.cwd(), targetFile),
      JSON.stringify(payload) + '\n',
      'utf8'
    );
  } catch (_) {}

  // ── User-registered handlers (DB sinks, webhooks, etc.) ────────────────────
  for (const handler of auditTrail['_handlers']) {
    try {
      await handler(payload);
    } catch (err) {
      console.error('[Audit] onLog handler threw:', err);
    }
  }
}

// ─── IntelligentAuditTrail ────────────────────────────────────────────────────

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
export class IntelligentAuditTrail {
  private detector = new AuditAnomalyDetector();
  private mode: 'TRAINING' | 'PRODUCTION' = 'TRAINING';

  /** @internal — accessed by {@link emitAuditLog} via string key to avoid exposing in public types. */
  _handlers: AuditLogHandler[] = [];

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
  onLog(handler: AuditLogHandler): this {
    this._handlers.push(handler);
    return this;
  }

  /**
   * Sets the operating mode of the audit trail.
   *
   * @param mode - `'TRAINING'` to collect baseline data, or `'PRODUCTION'` to
   *   enable live anomaly detection and production log persistence.
   */
  setMode(mode: 'TRAINING' | 'PRODUCTION'): void {
    this.mode = mode;
    console.log(`\x1b[36m[Audit Trail]\x1b[0m Mode initialized as: ${mode}`);
  }

  /**
   * Populates the anomaly-detection engine with pre-recorded baseline data and
   * switches the trail to `PRODUCTION` mode automatically.
   *
   * @param source - Either an array of {@link AuditLogMetadata} objects, or a
   *   file-system path to a `.jsonl` file where each line is a JSON-encoded log
   *   entry. Relative paths are resolved from `process.cwd()`.
   */
  loadBaseline(source: AuditLogMetadata[] | string): void {
    let baselineData: AuditLogMetadata[] = [];

    if (typeof source === 'string') {
      try {
        const filePath = path.resolve(process.cwd(), source);
        const fileContent = fs.readFileSync(filePath, 'utf8');
        baselineData = fileContent
          .split('\n')
          .filter(line => line.trim().length > 0)
          .map(line => JSON.parse(line));
      } catch (err) {
        console.error(`\x1b[31m[Audit ML] Failed to load baseline file:\x1b[0m`, err);
        return;
      }
    } else if (Array.isArray(source)) {
      baselineData = source;
    } else {
      console.error(`\x1b[31m[Audit ML] Invalid baseline format.\x1b[0m`);
      return;
    }

    this.detector.loadPresetBaseline(baselineData);
    this.mode = 'PRODUCTION';
  }

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
  async processEvent(
    resource: string,
    action: AuditLogMetadata['action'],
    duration: number
  ): Promise<Partial<AuditLogMetadata>> {
    if (this.mode === 'TRAINING') return { severity: 'TRAINING', anomalyScore: 0 };
    try {
      const analysis = this.detector.analyzeActivity(resource, action, duration);
      return {
        severity: analysis.isSuspicious ? 'SUSPICIOUS' : 'NORMAL',
        anomalyScore: parseFloat(analysis.score.toFixed(4)),
      };
    } catch (_) {
      return { severity: 'TRAINING', anomalyScore: 0 };
    }
  }
}

/**
 * Module-level singleton of {@link IntelligentAuditTrail}.
 * Import this instance to call {@link IntelligentAuditTrail.setMode},
 * {@link IntelligentAuditTrail.loadBaseline}, or
 * {@link IntelligentAuditTrail.onLog} during application startup.
 */
export const auditTrail = new IntelligentAuditTrail();

// ─── withAudit ────────────────────────────────────────────────────────────────

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
export function withAudit<T extends any[], R>(
  actionFunc: (...args: T) => Promise<R>,
  options: { resource: string; functionName?: string }
): (...args: T) => Promise<R> {
  return async (...args: T): Promise<R> => {
    const ctx: AuditContext = {
      actions: new Set<AuditLogMetadata['action']>(),
      functionName: options.functionName ?? 'unknown',
      resource: options.resource,
    };
    const startTime = Date.now();

    const flush = async (status: 'SUCCESS' | 'FAILURE'): Promise<void> => {
      const duration = Date.now() - startTime;
      if (ctx.actions.size === 0) ctx.actions.add('READ');

      for (const actionType of ctx.actions) {
        const { severity, anomalyScore } = await auditTrail.processEvent(
          options.resource, actionType, duration
        );
        await emitAuditLog({
          resource: options.resource,
          functionName: ctx.functionName,
          action: actionType,
          timestamp: new Date().toISOString(),
          duration,
          status,
          severity: severity as AuditLogMetadata['severity'],
          anomalyScore,
        });
      }
    };

    try {
      const result = await networkQueryTracker.run(ctx, () => actionFunc(...args));
      await flush('SUCCESS');
      return result;
    } catch (error) {
      if (isNextInternalThrow(error)) {
        await flush('SUCCESS');
        throw error;
      }

      const duration = Date.now() - startTime;
      const finalActions =
        ctx.actions.size > 0
          ? Array.from(ctx.actions)
          : (['UNKNOWN'] as AuditLogMetadata['action'][]);

      for (const actionType of finalActions) {
        console.error(
          `[Audit Failure] ${JSON.stringify({
            resource: options.resource,
            functionName: ctx.functionName,
            action: actionType,
            timestamp: new Date().toISOString(),
            duration,
            status: 'FAILURE',
            error: error instanceof Error ? error.message : 'Unknown',
          })}`
        );
      }
      throw error;
    }
  };
}

// ─── auditServerAction ────────────────────────────────────────────────────────

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
export function auditServerAction<T extends any[], R>(
  actionFunc: (...args: T) => Promise<R>,
  options: { resource: string; functionName?: string }
): (...args: T) => Promise<R> {
  const resolvedName = options.functionName ?? actionFunc.name ?? 'unknown';
  return withAudit(actionFunc, { ...options, functionName: resolvedName });
}

// ─── trackActions ─────────────────────────────────────────────────────────────

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
export function trackActions<T extends Record<string, any>>(actions: T, resourceName: string): T {
  const wrappedCache = new Map<string | symbol, any>();

  return new Proxy(actions, {
    get(target, propKey, receiver) {
      if (wrappedCache.has(propKey)) return wrappedCache.get(propKey);

      const originalValue = Reflect.get(target, propKey, receiver);

      if (typeof originalValue === 'function') {
        const funcName = (originalValue as Function).name || propKey.toString();

        const wrapped = withAudit(originalValue as any, {
          resource: resourceName,
          functionName: funcName,
        });

        for (const key of Reflect.ownKeys(originalValue)) {
          if (['length', 'name', 'prototype', 'caller', 'arguments'].includes(key as string)) continue;
          try { Reflect.set(wrapped, key, Reflect.get(originalValue, key)); } catch (_) {}
        }

        wrappedCache.set(propKey, wrapped);
        return wrapped;
      }

      return originalValue;
    },
  });
}