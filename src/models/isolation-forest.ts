/* ./src/models/isolation-forest.ts */
// @ts-ignore
import { IsolationForest } from 'isolation-forest';

/**
 * Utility to convert raw Audit Metadata into numerical vectors for the ML model.
 * Features captured: [HourOfDay, ActionType, Duration, ResourceType]
 */
export class AuditDataTransformer {
  private resourceMap: Map<string, number> = new Map();
  private actionMap: Record<string, number> = {
    'CREATE': 1,
    'READ': 2,
    'UPDATE': 3,
    'DELETE': 4
  };

  /**
   * Transforms a log entry into a numerical array.
   * Standardizing inputs is critical for Isolation Forest accuracy.
   */
  transform(resource: string, action: string, duration: number, timestamp: string): number[] {
    // 1. Hour of Day (0-23) - Detects "after-hours" anomalies
    const hour = new Date(timestamp).getHours();

    // 2. Action Type (Numerical mapping)
    const actionVal = this.actionMap[action] || 0;

    // 3. Resource Mapping (Auto-indexing unique resources)
    if (!this.resourceMap.has(resource)) {
      this.resourceMap.set(resource, this.resourceMap.size + 1);
    }
    const resourceVal = this.resourceMap.get(resource) || 0;

    // 4. LOGARITHMIC FEATURE SCALING & WEIGHTING
    // We use Math.log2() to compress the mathematical space. 
    // Without this, a 50,000ms outlier stretches the space so far that a 
    // 15,000ms attack looks "close to zero" and gets grouped with the normal data.
    const scaledDuration = Math.log2(duration + 1);

    // We duplicate the scaled duration to prevent "Categorical Swamping".
    return [hour, actionVal, resourceVal, scaledDuration, scaledDuration, scaledDuration, scaledDuration];
  }
}

/**
 * Intelligent Anomaly Detector
 * Implements a preset baseline strategy for Review-by-Exception (RbE).
 */
export class AuditAnomalyDetector {
  private model: any;
  private transformer: AuditDataTransformer;
  private isTrained: boolean = false;
  
  // Enterprise Feature: Auto-calibrated threshold
  private dynamicThreshold: number = 0.60; 

  constructor() {
    this.model = new IsolationForest(100); // 100 trees is a solid baseline
    this.transformer = new AuditDataTransformer();
  }

  /**
   * Loads a preset baseline of 'Normal' activities.
   * Auto-calibrates the anomaly threshold based on the specific dataset distribution.
   */
  loadPresetBaseline(rawBaseline: Array<{ resource: string, action: any, duration: number, timestamp: string }>) {
    const trainingData = rawBaseline.map(item => 
      this.transformer.transform(item.resource, item.action, item.duration, item.timestamp)
    );

    // ==========================================
    // ENTERPRISE FIX: CLONED SYNTHETIC OUTLIERS
    // ==========================================
    // Find the actual max normal duration to scale our outliers realistically
    const maxNormalDuration = Math.max(...rawBaseline.map(b => b.duration));

    const syntheticOutliers = [];
    const outlierCount = Math.max(10, Math.floor(rawBaseline.length * 0.10)); // Inject 10%
    
    for (let i = 0; i < outlierCount; i++) {
      // We clone a REAL event (e.g., READ Article) and mutate ONLY its duration.
      // This forces the ML to learn that extreme duration is bad EVEN IF the action/resource is normal!
      const baseEvent = rawBaseline[Math.floor(Math.random() * rawBaseline.length)];
      
      // Inject durations that are 3x to 10x higher than the absolute max normal duration
      const extremeDuration = maxNormalDuration * (3 + Math.random() * 7); 
      
      syntheticOutliers.push(
        this.transformer.transform(baseEvent.resource, baseEvent.action, extremeDuration, baseEvent.timestamp)
      );
    }

    // Train the model on BOTH the normal baseline and the cloned boundaries
    this.model.fit([...trainingData, ...syntheticOutliers]);
    this.isTrained = true;

    // ==========================================
    // DYNAMIC AUTO-CALIBRATION (98th Percentile)
    // ==========================================
    // We calculate the threshold using ONLY the normal training data.
    const baselineScores = this.model.scores(trainingData);
    
    // Sort scores ascending
    const sortedScores = [...baselineScores].sort((a, b) => a - b);
    
    // We use the 98th percentile for a robust threshold, ignoring rare baseline spikes.
    const p98Index = Math.floor(sortedScores.length * 0.98);
    const robustMaxNormal = sortedScores[p98Index];
    
    // Tighter margin (+0.015) now that the space is logarithmically scaled
    this.dynamicThreshold = robustMaxNormal + 0.015;

    const absoluteMax = sortedScores[sortedScores.length - 1];

    console.log(`[ML Engine]: Baseline loaded with ${trainingData.length} normal samples (+${outlierCount} synthetic boundaries).`);
    console.log(`[ML Engine]: Auto-calibrated Threshold to ${this.dynamicThreshold.toFixed(4)} (98th Pct: ${robustMaxNormal.toFixed(4)} | Abs Max: ${absoluteMax.toFixed(4)})`);
  }

  /**
   * Analyzes a new activity against the baseline.
   * @returns score (0 to 1) and whether it exceeds the dynamic threshold.
   */
  analyzeActivity(resource: string, action: string, duration: number): { score: number; isSuspicious: boolean } {
    if (!this.isTrained) {
      throw new Error("Model must be trained with a baseline before analysis.");
    }

    const vector = this.transformer.transform(resource, action, duration, new Date().toISOString());
    const scores = this.model.scores([vector]);
    const score = scores[0];

    return {
      score,
      isSuspicious: score > this.dynamicThreshold
    };
  }
}