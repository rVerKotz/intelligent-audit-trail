import { AuditAnomalyDetector } from '../models/isolation-forest';
import fs from 'fs';
import path from 'path';
import { AsyncLocalStorage } from 'async_hooks';

/**
 * Metadata structure for audit logs.
 * Defines the schema for tracking resource access, actions, and anomaly detection results.
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
 * Call Stack Reflection Utility
 * Analyzes the JavaScript execution stack to identify the original caller function
 * while filtering out internal Node.js, Next.js, and SDK-related frames.
 * @returns The name of the function that initiated the request.
 */
function getCallerFunctionName(): string {
  try {
    const stack = new Error().stack;
    if (!stack) return 'Direct_Client_Action';

    const lines = stack.split('\n');
    for (const line of lines) {
      if (
        line.includes('node:') || 
        line.includes('node_modules') || 
        line.includes('audit.ts') || 
        line.includes('globalThis.fetch') ||
        line.includes('next/dist')
      ) {
        continue;
      }

      const match = line.match(/at\s+(?:async\s+)?([a-zA-Z0-9_$]+)\s*(?:\[as\s+[^\]]+\])?\s*\(/);
      if (match && match[1]) {
        return match[1];
      }
    }
  } catch (e) {
    // Fallback in case stack trace generation is restricted
  }
  return 'Direct_Client_Action';
}

/**
 * Global Network Interceptor Storage
 * Uses AsyncLocalStorage to propagate audit context across asynchronous boundaries.
 */
const networkQueryTracker = new AsyncLocalStorage<Set<AuditLogMetadata['action']>>();

/**
 * Autonomous Runtime Fetch Interceptor
 * Patches globalThis.fetch to automatically detect and log network activity.
 * Supports both context-aware logging via networkQueryTracker and autonomous logging
 * for direct client-side fetch calls.
 */
if (typeof globalThis !== 'undefined' && globalThis.fetch) {
  const originalFetch = globalThis.fetch;
  
  if (!(globalThis as any).__auditFetchPatched) {
    globalThis.fetch = async function (...args) {
      const store = networkQueryTracker.getStore();
      
      const isReqObj = typeof Request !== 'undefined' && args[0] instanceof Request;
      const requestUrl = (isReqObj ? (args[0] as Request).url : args[0]?.toString()) || '';
      const method = (isReqObj ? (args[0] as Request).method : (args[1] as RequestInit)?.method) || 'GET';
      const methodUpper = method.toUpperCase();

      let detectedAction: AuditLogMetadata['action'] | null = null;
      let detectedResource: string | null = null;

      if (requestUrl.includes('/v1/')) {
        // Database CRUD Routing
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
          } catch (e) {
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
        } 
        // Authentication Routing
        else if (requestUrl.includes('/auth/v1/')) {
          detectedResource = 'Auth';
          if (requestUrl.includes('signup')) detectedAction = 'CREATE';
          else if (requestUrl.includes('token') || requestUrl.includes('user')) detectedAction = 'READ';
          else if (methodUpper === 'POST') detectedAction = 'CREATE';
          else if (methodUpper === 'PUT') detectedAction = 'UPDATE';
          else if (methodUpper === 'GET') detectedAction = 'READ';
        } 
        // Storage Routing
        else if (requestUrl.includes('/storage/v1/')) {
          detectedResource = 'Storage';
          if (methodUpper === 'POST' || methodUpper === 'PUT') detectedAction = 'CREATE';
          if (methodUpper === 'DELETE') detectedAction = 'DELETE';
          if (methodUpper === 'GET') detectedAction = 'READ';
        }

        if (detectedAction) {
          if (store) {
            store.add(detectedAction);
          } else {
            const startTime = Date.now();
            try {
              const result = await originalFetch.apply(this, args);
              const duration = Date.now() - startTime;
              
              const finalResource = detectedResource || 'UnknownResource';
              const { severity, anomalyScore } = await auditTrail.processEvent(finalResource, detectedAction, duration);
              
              const auditPayload: AuditLogMetadata = {
                resource: finalResource,
                functionName: getCallerFunctionName(),
                action: detectedAction,
                timestamp: new Date().toISOString(),
                duration,
                status: result.ok ? 'SUCCESS' : 'FAILURE',
                severity: severity as any,
                anomalyScore,
              };
              
              if (severity === 'SUSPICIOUS') {
                console.warn(`\x1b[33m[AUDIT ALERT]\x1b[0m ${JSON.stringify(auditPayload)}`);
              } else if (severity === 'TRAINING') {
                console.info(`[AUDIT TRAINING LOG] ${JSON.stringify(auditPayload)}`);
                try {
                  fs.appendFileSync(path.join(process.cwd(), 'audit-baseline.jsonl'), JSON.stringify(auditPayload) + '\n', 'utf8');
                } catch (err) {}
              } else {
                console.log(`[Audit Captured] ${JSON.stringify(auditPayload)}`);
              }

              return result;
            } catch (error) {
              throw error;
            }
          }
        }
      }

      return originalFetch.apply(this, args);
    };
    (globalThis as any).__auditFetchPatched = true;
  }
}

/**
 * Intelligent Audit Trail Controller
 * Manages anomaly detection and audit log processing modes (Training vs. Production).
 */
export class IntelligentAuditTrail {
  private detector = new AuditAnomalyDetector();
  private mode: 'TRAINING' | 'PRODUCTION' = 'TRAINING';

  /**
   * Updates the operating mode of the audit trail.
   * @param mode - The system mode (TRAINING or PRODUCTION).
   */
  setMode(mode: 'TRAINING' | 'PRODUCTION') {
    this.mode = mode;
    console.log(`\x1b[36m[Audit Trail]\x1b[0m Mode initialized as: ${mode}`);
  }

  /**
   * Populates the anomaly detection engine with baseline data.
   * @param source - Either an array of audit logs or a file path to a .jsonl baseline.
   */
  loadBaseline(source: any[] | string) {
    let baselineData: any[] = [];

    if (typeof source === 'string') {
      try {
        const filePath = path.resolve(process.cwd(), source);
        const fileContent = fs.readFileSync(filePath, 'utf8');
        baselineData = fileContent.split('\n').filter(line => line.trim().length > 0).map(line => JSON.parse(line));
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
   * Analyzes an audit event for suspicious activity.
   * @param resource - The resource identifier.
   * @param action - The type of operation performed.
   * @param duration - Execution time in milliseconds.
   * @returns Partial metadata containing severity and anomaly score.
   */
  async processEvent(resource: string, action: AuditLogMetadata['action'], duration: number): Promise<Partial<AuditLogMetadata>> {
    if (this.mode === 'TRAINING') return { severity: 'TRAINING', anomalyScore: 0 };
    try {
      const analysis = this.detector.analyzeActivity(resource, action, duration);
      return {
        severity: analysis.isSuspicious ? 'SUSPICIOUS' : 'NORMAL',
        anomalyScore: parseFloat(analysis.score.toFixed(4))
      };
    } catch (e) {
      return { severity: 'TRAINING', anomalyScore: 0 };
    }
  }
}

export const auditTrail = new IntelligentAuditTrail();

/**
 * Audit Execution Context Wrapper
 * Wraps an asynchronous function within an audit context. It tracks network
 * activity triggered by the function and accounts for Next.js cache hits.
 * @param actionFunc - The asynchronous function to be audited.
 * @param options - Configuration including resource name and optional function identifier.
 * @returns The result of the wrapped function.
 */
export function withAudit<T extends any[], R>(
  actionFunc: (...args: T) => Promise<R>,
  options: { resource: string; functionName?: string } 
) {
  return async (...args: T): Promise<R> => {
    const runtimeActions = new Set<AuditLogMetadata['action']>();
    const startTime = Date.now();
    
    try {
      const result = await networkQueryTracker.run(runtimeActions, async () => {
        return await actionFunc(...args);
      });
      
      const duration = Date.now() - startTime;
      
      // Implicit READ detection for cached operations
      if (runtimeActions.size === 0) {
        runtimeActions.add('READ');
      }

      const finalActions = Array.from(runtimeActions);

      for (const actionType of finalActions) {
        const { severity, anomalyScore } = await auditTrail.processEvent(options.resource, actionType, duration);

        const auditPayload: AuditLogMetadata = {
          resource: options.resource,
          functionName: options.functionName,
          action: actionType,
          timestamp: new Date().toISOString(),
          duration,
          status: 'SUCCESS',
          severity: severity as any,
          anomalyScore,
        };

        if (severity === 'SUSPICIOUS') {
          console.warn(`\x1b[33m[AUDIT ALERT]\x1b[0m ${JSON.stringify(auditPayload)}`);
        } else if (severity === 'TRAINING') {
          console.info(`[AUDIT TRAINING LOG] ${JSON.stringify(auditPayload)}`);
          try {
            fs.appendFileSync(path.join(process.cwd(), 'audit-baseline.jsonl'), JSON.stringify(auditPayload) + '\n', 'utf8');
          } catch (err) {}
        } else {
          console.log(`[Audit Captured] ${JSON.stringify(auditPayload)}`);
        }
      }

      return result;
    } catch (error) {
      const finalActions = runtimeActions.size > 0 ? Array.from(runtimeActions) : ['UNKNOWN'];
      for (const actionType of finalActions) {
        console.error(`[Audit Failure] ${JSON.stringify({ resource: options.resource, functionName: options.functionName, action: actionType, timestamp: new Date().toISOString(), error: error instanceof Error ? error.message : 'Unknown' })}`);
      }
      throw error;
    }
  };
}

/**
 * Transparent Proxy Wrapper for Service Objects
 * Automatically applies 'withAudit' to all methods within an object. It maintains
 * a local cache of wrapped functions to ensure stable identity across renders,
 * which is critical for Next.js Server Action references.
 * @param actions - The service or object containing methods to track.
 * @param resourceName - The logical resource name for the audit logs.
 * @returns A proxied version of the input object with automatic auditing.
 */
export function trackActions<T extends Record<string, any>>(actions: T, resourceName: string): T {
  const wrappedCache = new Map<string | symbol, any>();

  return new Proxy(actions, {
    get(target, propKey, receiver) {
      if (wrappedCache.has(propKey)) {
        return wrappedCache.get(propKey);
      }

      const originalValue = Reflect.get(target, propKey, receiver);
      
      if (typeof originalValue === 'function') {
        const funcName = (originalValue as Function).name || "";
        const finalFunctionName = funcName || propKey.toString(); 
        
        const wrapped = withAudit(originalValue as any, { 
          resource: resourceName, 
          functionName: finalFunctionName 
        });

        for (const key of Reflect.ownKeys(originalValue)) {
          if (key === 'length' || key === 'name' || key === 'prototype' || key === 'caller' || key === 'arguments') continue;
          try { Reflect.set(wrapped, key, Reflect.get(originalValue, key)); } catch (e) {} 
        }

        wrappedCache.set(propKey, wrapped);
        return wrapped;
      }
      return originalValue;
    }
  });
}