import {
  InputShield as NativeInputShield,
  analyze as nativeAnalyze,
  shouldBlock as nativeShouldBlock,
  JsThreatAssessment,
  JsShieldConfig,
} from './index.node';

export interface Threat {
  category: string;
  level: string;
  description: string;
  confidence: number;
  evidence: string;
}

export interface ThreatAssessment {
  inputHash: string;
  threats: Threat[];
  overallLevel: string;
  riskScore: number;
  shouldBlock: boolean;
  analysisTimeUs: number;
}

export interface ShieldConfig {
  blockThreshold?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  maxInputLength?: number;
  enableCanaryTokens?: boolean;
}

/**
 * High-performance input shield for AI agent security
 */
export class InputShield {
  private native: NativeInputShield;

  constructor(config?: ShieldConfig) {
    this.native = new NativeInputShield(config ? {
      block_threshold: config.blockThreshold,
      max_input_length: config.maxInputLength,
      enable_canary_tokens: config.enableCanaryTokens,
    } : undefined);
  }

  /**
   * Analyze input for security threats
   */
  analyze(input: string): ThreatAssessment {
    const result = this.native.analyze(input);
    return {
      inputHash: result.input_hash,
      threats: result.threats,
      overallLevel: result.overall_level,
      riskScore: result.risk_score,
      shouldBlock: result.should_block,
      analysisTimeUs: result.analysis_time_us,
    };
  }

  /**
   * Generate a canary token for embedding in system prompts
   */
  generateCanary(context: string): string {
    return this.native.generate_canary(context);
  }

  /**
   * Check if output contains leaked canary tokens
   */
  checkOutput(output: string): Threat[] {
    return this.native.check_output(output);
  }
}

/**
 * Quick analysis using default settings
 */
export function analyze(input: string): ThreatAssessment {
  const result = nativeAnalyze(input);
  return {
    inputHash: result.input_hash,
    threats: result.threats,
    overallLevel: result.overall_level,
    riskScore: result.risk_score,
    shouldBlock: result.should_block,
    analysisTimeUs: result.analysisTimeUs,
  };
}

/**
 * Quick check if input should be blocked
 */
export function shouldBlock(input: string): boolean {
  return nativeShouldBlock(input);
}

/**
 * Middleware for Express.js
 */
export function expressMiddleware(config?: ShieldConfig) {
  const shield = new InputShield(config);
  
  return (req: any, res: any, next: any) => {
    const body = req.body;
    
    // Check all string values in body
    const checkValue = (value: any): boolean => {
      if (typeof value === 'string') {
        const result = shield.analyze(value);
        if (result.shouldBlock) {
          res.status(400).json({
            error: 'Security threat detected',
            level: result.overallLevel,
            score: result.riskScore,
          });
          return false;
        }
      } else if (typeof value === 'object' && value !== null) {
        for (const key in value) {
          if (!checkValue(value[key])) return false;
        }
      }
      return true;
    };
    
    if (checkValue(body)) {
      next();
    }
  };
}

/**
 * Decorator for protecting async functions (TypeScript)
 */
export function protect(config?: ShieldConfig) {
  const shield = new InputShield(config);
  
  return function <T extends (...args: any[]) => Promise<any>>(
    target: any,
    propertyKey: string,
    descriptor: TypedPropertyDescriptor<T>
  ) {
    const originalMethod = descriptor.value!;
    
    descriptor.value = async function (...args: any[]) {
      for (const arg of args) {
        if (typeof arg === 'string') {
          const result = shield.analyze(arg);
          if (result.shouldBlock) {
            throw new SecurityError(
              `Security threat detected: ${result.overallLevel}`,
              result
            );
          }
        }
      }
      return originalMethod.apply(this, args);
    } as T;
    
    return descriptor;
  };
}

export class SecurityError extends Error {
  constructor(message: string, public assessment: ThreatAssessment) {
    super(message);
    this.name = 'SecurityError';
  }
}
