import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  checkTpmAvailability,
  enableTpmMock,
  disableTpmMock,
  isTpmMockEnabled,
  tpmSeal,
  tpmUnseal,
  sealMasterKey,
  unsealMasterKey,
  hasSealedMasterKey,
  removeSealedMasterKey,
} from '../src/tpm-sealer.js';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('tpm-sealer', () => {
  // Mock mode test data
  const mockSeed = Buffer.from('mock-tpm-seed-data');
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpm-test-'));
  });

  afterEach(() => {
    disableTpmMock();
    // Clean up temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  describe('mock mode', () => {
    it('should enable and disable mock mode', () => {
      expect(isTpmMockEnabled()).toBe(false);

      enableTpmMock(mockSeed);

      expect(isTpmMockEnabled()).toBe(true);

      disableTpmMock();

      expect(isTpmMockEnabled()).toBe(false);
    });

    it('should store and return original data in mock mode', () => {
      const customUnseal = (data: Buffer) => Buffer.from('unsealed-data');
      enableTpmMock(mockSeed, customUnseal);

      const testData = Buffer.alloc(32);
      testData.write('test-key-data');

      const sealed = tpmSeal(testData);
      const unsealed = tpmUnseal(sealed);

      // Mock mode stores the original data and returns it
      expect(unsealed.equals(testData)).toBe(true);
    });

    it('should use custom public key', () => {
      const customPublicKey = Buffer.from('custom-public-key');
      enableTpmMock(mockSeed, undefined, customPublicKey);

      const sealed = tpmSeal(Buffer.from('test-key'.padEnd(32, '\0')));

      expect(sealed.publicKey.equals(customPublicKey)).toBe(true);
    });
  });

  describe('tpmSeal / tpmUnseal', () => {
    beforeEach(() => {
      enableTpmMock(mockSeed);
    });

    it('should seal and unseal 32-byte data', () => {
      const originalData = Buffer.alloc(32);
      originalData.write('my-secret-master-key-1234567890');
      expect(originalData.length).toBe(32);

      const sealed = tpmSeal(originalData);
      expect(sealed.version).toBe(1);
      expect(sealed.algorithm).toBe('mock-aes-256-gcm');
      expect(sealed.publicKey.length).toBeGreaterThan(0);
      expect(sealed.createdAt).toBeGreaterThan(0);

      const unsealed = tpmUnseal(sealed);
      expect(unsealed.equals(originalData)).toBe(true);
    });

    it('should produce different sealed data each seal (mock)', () => {
      const data = Buffer.alloc(32);
      data.write('test-key-data-12345678901');

      const sealed1 = tpmSeal(data);
      const sealed2 = tpmSeal(data);

      // Should be different due to counter in mock
      expect(sealed1.sealedData.equals(sealed2.sealedData)).toBe(false);

      // But both should unseal to the same data
      expect(tpmUnseal(sealed1).equals(data)).toBe(true);
      expect(tpmUnseal(sealed2).equals(data)).toBe(true);
    });

    it('should throw on invalid data length', () => {
      const shortData = Buffer.from('short');
      expect(() => tpmSeal(shortData)).toThrow('Sealed data must be 32 bytes');
    });
  });

  describe('sealMasterKey / unsealMasterKey', () => {
    beforeEach(() => {
      enableTpmMock(mockSeed);
    });

    it('should seal and persist master key to disk', () => {
      const masterKey = Buffer.alloc(32);
      masterKey.write('master-key-1234567890123456');
      const storagePath = path.join(tempDir, 'master-key.sealed');

      sealMasterKey(masterKey, storagePath);

      expect(fs.existsSync(storagePath)).toBe(true);

      const loaded = unsealMasterKey(storagePath);
      expect(loaded.equals(masterKey)).toBe(true);
    });

    it('should create parent directories if needed', () => {
      const masterKey = Buffer.alloc(32);
      masterKey.write('master-key-1234567890123456');
      const nestedPath = path.join(tempDir, 'nested', 'dirs', 'master-key.sealed');

      sealMasterKey(masterKey, nestedPath);

      expect(fs.existsSync(nestedPath)).toBe(true);
    });

    it('should throw when sealed key file not found', () => {
      expect(() => unsealMasterKey('/nonexistent/path')).toThrow('Sealed key file not found');
    });
  });

  describe('hasSealedMasterKey / removeSealedMasterKey', () => {
    beforeEach(() => {
      enableTpmMock(mockSeed);
    });

    it('should check for sealed key existence', () => {
      const storagePath = path.join(tempDir, 'master-key.sealed');
      const key = Buffer.alloc(32);
      key.write('key');

      expect(hasSealedMasterKey(storagePath)).toBe(false);

      sealMasterKey(key, storagePath);

      expect(hasSealedMasterKey(storagePath)).toBe(true);
    });

    it('should remove sealed key', () => {
      const storagePath = path.join(tempDir, 'master-key.sealed');
      const key = Buffer.alloc(32);
      key.write('key');
      sealMasterKey(key, storagePath);

      expect(hasSealedMasterKey(storagePath)).toBe(true);

      removeSealedMasterKey(storagePath);

      expect(hasSealedMasterKey(storagePath)).toBe(false);
    });

    it('should handle remove on non-existent file', () => {
      const storagePath = path.join(tempDir, 'nonexistent.sealed');

      // Should not throw
      expect(() => removeSealedMasterKey(storagePath)).not.toThrow();
    });
  });

  describe('checkTpmAvailability', () => {
    it('should report mock device when mock enabled', () => {
      enableTpmMock(mockSeed);

      const availability = checkTpmAvailability();

      expect(availability.available).toBe(true);
      expect(availability.devicePath).toBe('mock');
    });
  });
});
