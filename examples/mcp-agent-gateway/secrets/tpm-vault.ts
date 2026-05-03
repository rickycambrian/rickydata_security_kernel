/**
 * TPM-Sealed Vault
 *
 * Provides TPM-based sealing/unsealing of the master encryption key.
 * Uses @rickydata/security-kernel package.
 */

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
} from '@rickydata/security-kernel';

export type { TpmSealedData, TpmAvailability } from '@rickydata/security-kernel';

export {
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
};
