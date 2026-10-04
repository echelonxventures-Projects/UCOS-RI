// Protocol types (contracts/context-runtime/semantics.md). Integers are bigint.

export interface Dimension {
  code: string;
  valueType?: string;
  weight: bigint;
  precedence: bigint;
  required: boolean;
  default?: unknown;
  normalize?: string;
  values?: unknown[] | null;
  hierarchy?: Record<string, string> | null;
  fromAsOf?: boolean;
}

export interface Constraint {
  dimension: string;
  op: string;
  values: unknown[];
}

export interface Candidate {
  id: string;
  scope: Constraint[];
  validFrom: string;
  validTo: string | null;
  priority: bigint;
  value: unknown;
}

export interface Context {
  values: Record<string, unknown>;
  asOf: string;
  cacheGranularitySeconds?: bigint;
}

export interface Config {
  dimensionPrecedence?: string[];
  conflictStrategy: string;
  cardinality: string;
  relaxationAllowed: boolean;
  fallbackChains?: string[];
  maxFallbackSteps?: bigint | null;
  configRef?: string | null;
}

export class World {
  readonly dims = new Map<string, Dimension>();
  readonly order: string[];
  constructor(dimensions: Dimension[]) {
    for (const d of dimensions) this.dims.set(d.code, d);
    this.order = dimensions
      .map((d) => d.code)
      .sort((a, b) => {
        const pa = this.dims.get(a)!.precedence;
        const pb = this.dims.get(b)!.precedence;
        if (pa !== pb) return pa < pb ? -1 : 1;
        return a < b ? -1 : a > b ? 1 : 0;
      });
  }
}
