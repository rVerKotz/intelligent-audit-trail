/**
 * Metadata structure for audit logs.
 * Defines the schema for tracking resource access, actions, and anomaly detection results.
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
 * Intelligent Audit Trail Controller
 * Manages anomaly detection and audit log processing modes (Training vs. Production).
 */
declare class IntelligentAuditTrail {
    private detector;
    private mode;
    /**
     * Updates the operating mode of the audit trail.
     * @param mode - The system mode (TRAINING or PRODUCTION).
     */
    setMode(mode: 'TRAINING' | 'PRODUCTION'): void;
    /**
     * Populates the anomaly detection engine with baseline data.
     * @param source - Either an array of audit logs or a file path to a .jsonl baseline.
     */
    loadBaseline(source: any[] | string): void;
    /**
     * Analyzes an audit event for suspicious activity.
     * @param resource - The resource identifier.
     * @param action - The type of operation performed.
     * @param duration - Execution time in milliseconds.
     * @returns Partial metadata containing severity and anomaly score.
     */
    processEvent(resource: string, action: AuditLogMetadata['action'], duration: number): Promise<Partial<AuditLogMetadata>>;
}
declare const auditTrail: IntelligentAuditTrail;
/**
 * Audit Execution Context Wrapper
 * Wraps an asynchronous function within an audit context. It tracks network
 * activity triggered by the function and accounts for Next.js cache hits.
 * @param actionFunc - The asynchronous function to be audited.
 * @param options - Configuration including resource name and optional function identifier.
 * @returns The result of the wrapped function.
 */
declare function withAudit<T extends any[], R>(actionFunc: (...args: T) => Promise<R>, options: {
    resource: string;
    functionName?: string;
}): (...args: T) => Promise<R>;
/**
 * Transparent Proxy Wrapper for Service Objects
 * Automatically applies 'withAudit' to all methods within an object. It maintains
 * a local cache of wrapped functions to ensure stable identity across renders,
 * which is critical for Next.js Server Action references.
 * @param actions - The service or object containing methods to track.
 * @param resourceName - The logical resource name for the audit logs.
 * @returns A proxied version of the input object with automatic auditing.
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

export { AuditAnomalyDetector, AuditDataTransformer, type AuditLogMetadata, IntelligentAuditTrail, auditTrail, trackActions, withAudit };
