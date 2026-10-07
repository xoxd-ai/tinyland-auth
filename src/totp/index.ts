








export {
  TOTPService,
  createTOTPService,
  type TOTPServiceConfig,
} from '../core/totp/index.js';


export {
  generateTOTPSecret,
  generateTOTPUri,
  generateTempPassword,
  generateTOTPQRCode,
  generateTOTPToken,
  getTOTPTimeRemaining,
} from './compat.js';


export type { TOTPSecret, EncryptedData } from '../types/auth.js';
