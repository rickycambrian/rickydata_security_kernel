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
  const originalPath = process.env.PATH;
  const originalTpmDevice = process.env.RICKYDATA_TPM_DEVICE_PATH;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpm-test-'));
  });

  afterEach(() => {
    disableTpmMock();
    process.env.PATH = originalPath;
    if (originalTpmDevice === undefined) {
      delete process.env.RICKYDATA_TPM_DEVICE_PATH;
    } else {
      process.env.RICKYDATA_TPM_DEVICE_PATH = originalTpmDevice;
    }
    // Clean up temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  function installFakeTpmTools(binDir: string): void {
    const script = `#!/bin/sh
cmd="$(basename "$0")"
value_for_flag() {
  flag="$1"
  shift
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "$flag" ]; then
      echo "$2"
      return 0
    fi
    shift
  done
}
case "$cmd" in
  tpm2_getcap)
    echo "TPM2_PT_MANUFACTURER: 0x5249434b"
    ;;
  tpm2_createprimary)
    ctx="$(value_for_flag -c "$@")"
    [ -n "$ctx" ] && printf primary > "$ctx"
    ;;
  tpm2_pcrread)
    out="$(value_for_flag -o "$@")"
    [ -n "$out" ] && printf pcr > "$out"
    ;;
  tpm2_createpolicy)
    policy="$(value_for_flag -L "$@")"
    [ -n "$policy" ] && printf policy > "$policy"
    ;;
  tpm2_create)
    in_file="$(value_for_flag -i "$@")"
    pub="$(value_for_flag -u "$@")"
    priv="$(value_for_flag -r "$@")"
    [ -n "$pub" ] && printf public > "$pub"
    [ -n "$priv" ] && cp "$in_file" "$priv"
    ;;
  tpm2_load)
    priv="$(value_for_flag -r "$@")"
    ctx="$(value_for_flag -c "$@")"
    cp "$priv" "$ctx"
    ;;
  tpm2_startauthsession)
    session="$(value_for_flag -S "$@")"
    [ -n "$session" ] && printf session > "$session"
    ;;
  tpm2_policypcr)
    ;;
  tpm2_unseal)
    ctx="$(value_for_flag -c "$@")"
    cat "$ctx"
    ;;
  tpm2_flushcontext)
    ;;
  *)
    echo "unexpected fake tpm command: $cmd" >&2
    exit 1
    ;;
esac
`;

    for (const command of [
      'tpm2_getcap',
      'tpm2_createprimary',
      'tpm2_create',
      'tpm2_load',
      'tpm2_unseal',
      'tpm2_pcrread',
      'tpm2_createpolicy',
      'tpm2_startauthsession',
      'tpm2_policypcr',
      'tpm2_flushcontext',
    ]) {
      const file = path.join(binDir, command);
      fs.writeFileSync(file, script, { mode: 0o755 });
    }
  }

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

  describe('real TPM command path', () => {
    it('should seal and unseal via tpm2 policy commands when TPM is available', () => {
      disableTpmMock();
      const binDir = path.join(tempDir, 'bin');
      fs.mkdirSync(binDir);
      installFakeTpmTools(binDir);
      const fakeDevice = path.join(tempDir, 'tpmrm0');
      fs.writeFileSync(fakeDevice, '');
      process.env.PATH = `${binDir}:${originalPath || ''}`;
      process.env.RICKYDATA_TPM_DEVICE_PATH = fakeDevice;

      const originalData = Buffer.alloc(32, 7);
      const sealed = tpmSeal(originalData);

      expect(sealed.algorithm).toBe('tpm2-policy-pcr');
      expect(sealed.pcrSelection).toBe('sha256:0,1,2,3,4,5,7');

      const unsealed = tpmUnseal(sealed);
      expect(unsealed.equals(originalData)).toBe(true);
    }, 15000);
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
