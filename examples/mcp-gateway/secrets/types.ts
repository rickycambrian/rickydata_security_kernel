/**
 * Secret Management Types
 *
 * These types define the structure for secure secret storage
 * with wallet-based user isolation.
 */

export interface EncryptedSecret {
  name: string;           // e.g., "EXA_API_KEY"
  encryptedValue: Buffer; // AES-256-GCM encrypted
  iv: Buffer;             // Initialization vector (12 bytes)
  authTag: Buffer;        // GCM authentication tag (16 bytes)
  createdAt: Date;
  usageCount: number;
}

export interface ServerSecrets {
  serverId: string;
  serverName: string;
  secrets: Map<string, EncryptedSecret>;
  createdAt: Date;
  lastUsedAt: Date;
}

export interface UserSecretVault {
  vaultKeyPrefix: string;  // First 8 chars of HMAC vault key (for logs only)
  userSalt: Buffer;        // 32 cryptographically random bytes for HKDF salt
  createdAt: Date;
  lastAccessAt: Date;
  servers: Map<string, ServerSecrets>;
}

export interface SecretRequirement {
  name: string;
  description: string;
  required: boolean;
  configured?: boolean;
}

export interface MissingSecretsError {
  error: 'missing_secrets';
  serverId: string;
  serverName: string;
  missingSecrets: Array<{
    name: string;
    description: string;
    required: boolean;
  }>;
  instructions: {
    howToGetKey: string;
    howToConfigure: string;
    exampleRequest: {
      method: 'POST';
      url: string;
      headers: Record<string, string>;
      body: Record<string, unknown>;
    };
    claudeDesktopConfig?: object;
  };
}

export interface StoreSecretsRequest {
  secrets: Record<string, string>;
}

export interface StoreSecretsResponse {
  success: true;
  stored: string[];
  serverId: string;
  serverName: string;
}

export interface SecretStatusResponse {
  serverId: string;
  serverName: string;
  configuredSecrets: string[];
  requiredSecrets: SecretRequirement[];
  missingSecrets: string[];
}

export interface DeleteSecretsResponse {
  success: true;
  deleted: string | string[];
}

export interface ListSecretsResponse {
  servers: Array<{
    serverId: string;
    serverName: string;
    secretCount: number;
  }>;
}

export interface DeleteAllSecretsResponse {
  success: true;
  deletedServers: string[];
  totalSecretsDeleted: number;
}
