/**
 * Centralized Sign-to-Derive Signing Message Registry
 *
 * All S2D signing messages in one place with version tracking.
 * CRITICAL: v1 messages are CHARACTER-IDENTICAL to production messages.
 * Any accidental change = permanent data loss for all users.
 */

export type S2DPurpose =
  | 'anthropic-apikey'
  | 'agent-secrets'
  | 'minimax-apikey'
  | 'openrouter-apikey'
  | 'zai-apikey'
  | 'deepseek-apikey'
  | 'gemini-apikey'
  | 'kimi-apikey'
  | 'opencode-apikey'
  | 'openai-apikey'
  | 'provider-api-keys'
  | 'codex-auth'
  | 'anthropic-oauth'
  | 'erc8004-derive';

interface SigningMessageVersion {
  version: number;
  getMessage: (wallet: string) => string;
}

const REGISTRY: Record<S2DPurpose, SigningMessageVersion[]> = {
  'anthropic-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key`,
    },
  ],
  'agent-secrets': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your secrets on MCP Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key`,
    },
  ],
  'minimax-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your MiniMax API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: minimax`,
    },
  ],
  'openrouter-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your OpenRouter API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: openrouter`,
    },
  ],
  'zai-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your Z.ai API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: zai`,
    },
  ],
  'deepseek-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your DeepSeek API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: deepseek`,
    },
  ],
  'gemini-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your Gemini API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: gemini`,
    },
  ],
  'kimi-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your Kimi API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: kimi`,
    },
  ],
  'opencode-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your OpenCode Go API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: opencode`,
    },
  ],
  'openai-apikey': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your OpenAI API key on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: openai`,
    },
  ],
  'provider-api-keys': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to unlock your rickydata provider vault.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-provider-vault-key\n\nThis only decrypts API keys you saved for this session. It does not authorize transactions or move funds.`,
    },
  ],
  'codex-auth': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your Codex subscription auth on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: codex`,
    },
  ],
  'anthropic-oauth': [
    {
      version: 1,
      getMessage: (wallet: string) =>
        `Sign this message to encrypt your Claude Code OAuth credentials on MCP Agent Gateway.\n\nWallet: ${wallet.toLowerCase()}\nPurpose: derive-encryption-key\nProvider: anthropic`,
    },
  ],
  'erc8004-derive': [
    {
      version: 1,
      getMessage: (_wallet: string) =>
        'Sign this message to derive your ERC-8004 agent key.\n\n' +
        'This signature will be used to create a deterministic private key ' +
        'for managing your on-chain agent identity. ' +
        'This does not grant access to your funds.',
    },
  ],
};

export function getLatestSigningMessage(purpose: S2DPurpose, wallet: string): string {
  const versions = REGISTRY[purpose];
  if (!versions || versions.length === 0) {
    throw new Error(`Unknown S2D purpose: ${purpose}`);
  }
  const latest = versions[versions.length - 1];
  return latest.getMessage(wallet);
}

export function getLatestVersion(purpose: S2DPurpose): number {
  const versions = REGISTRY[purpose];
  if (!versions || versions.length === 0) {
    throw new Error(`Unknown S2D purpose: ${purpose}`);
  }
  return versions[versions.length - 1].version;
}

export function getSigningMessage(purpose: S2DPurpose, wallet: string, version: number): string {
  const versions = REGISTRY[purpose];
  const entry = versions?.find(v => v.version === version);
  if (!entry) {
    throw new Error(`No version ${version} for S2D purpose: ${purpose}`);
  }
  return entry.getMessage(wallet);
}

export function getAllPurposes(): S2DPurpose[] {
  return Object.keys(REGISTRY) as S2DPurpose[];
}
