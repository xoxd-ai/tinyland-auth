








import { createHash } from 'crypto';





export interface CertificateHeaders {
  
  clientCert?: string;
  
  clientSubject?: string;
  
  clientVerify?: string;
  
  clientIssuer?: string;
}




export interface CertificateInfo {
  isValid: boolean;
  fingerprint?: string;
  subject?: string;
  issuer?: string;
  validFrom?: Date;
  validTo?: Date;
}




/**
 * Options for client-certificate checks.
 *
 * There is no development or bypass option (1.0.0, RP2): no host or NODE_ENV
 * admits a request that carries no forwarded certificate headers. Unknown keys,
 * such as a stale pre-1.0 development flag, are ignored.
 *
 * Trust model: these checks read headers set by the TLS-terminating proxy and
 * trust them. The proxy must overwrite or strip every client-supplied copy of
 * the certificate headers. Without `validFingerprints`, a forwarded subject
 * with the verify header absent or `NONE` is admitted, so set
 * `validFingerprints` wherever the edge is not guaranteed to strip them.
 */
export interface MTLSOptions {
  /** When set, only certificates whose `sha256:` fingerprint is listed pass. */
  validFingerprints?: Set<string>;
}
























export function extractCertificate(
  headers: CertificateHeaders,
  options: MTLSOptions = {}
): CertificateInfo {
  
  if (
    headers.clientVerify &&
    headers.clientVerify !== 'SUCCESS' &&
    headers.clientVerify !== 'NONE'
  ) {
    return { isValid: false };
  }

  
  if (!headers.clientCert && !headers.clientSubject) {
    return { isValid: false };
  }

  
  let fingerprint = '';
  if (headers.clientCert) {
    const cleanCert = decodeURIComponent(headers.clientCert)
      .replace(/\s+/g, '\n')
      .replace(/-----BEGIN\sCERTIFICATE-----/, '-----BEGIN CERTIFICATE-----')
      .replace(/-----END\sCERTIFICATE-----/, '-----END CERTIFICATE-----');

    fingerprint = 'sha256:' + createHash('sha256').update(cleanCert).digest('hex');
  }

  
  const isValid = options.validFingerprints
    ? options.validFingerprints.has(fingerprint)
    : true;

  return {
    isValid,
    fingerprint,
    subject: headers.clientSubject || 'Unknown',
    issuer: headers.clientIssuer || 'Unknown',
    validFrom: new Date(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  };
}





export function getCertificateFingerprint(
  headers: CertificateHeaders,
  options: MTLSOptions = {}
): string | null {
  const certInfo = extractCertificate(headers, options);
  return certInfo.isValid ? certInfo.fingerprint || null : null;
}
