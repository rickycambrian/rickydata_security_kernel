/**
 * Security Kernel - Type Definitions
 */

import type { Buffer } from 'node:buffer';

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export interface TpmSealedData {
  version: number;
  sealedData: Buffer;
  publicKey: Buffer;
  algorithm: string;
  createdAt: number;
}

export interface TpmAvailability {
  available: boolean;
  reason?: string;
  devicePath?: string;
}

export interface SealedMasterKeyJson {
  version: number;
  sealedData: string;
  publicKey: string;
  algorithm: string;
  createdAt: number;
}

export interface SignToDeriveResult {
  encrypted: string;
  iv: string;
  authTag: string;
}
