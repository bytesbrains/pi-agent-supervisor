export interface SessionState {
  toolCalls: Array<{ tool: string; timestamp: number }>;
  errorCount: number;
  consecutiveErrors: number;
  blockedCount: number;
  lastEscalation: number;
  contextBudget: { used: number; total: number } | null;
}

export let state: SessionState = {
  toolCalls: [], errorCount: 0, consecutiveErrors: 0, blockedCount: 0, lastEscalation: 0, contextBudget: null,
};

export function resetState() {
  state = { toolCalls: [], errorCount: 0, consecutiveErrors: 0, blockedCount: 0, lastEscalation: 0, contextBudget: null };
}
