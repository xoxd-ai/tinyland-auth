







import type { RequestEvent } from '@sveltejs/kit';
import {
  extractCertificate as coreExtractCertificate,
  getCertificateFingerprint as coreGetCertificateFingerprint,
  type CertificateHeaders,
  type CertificateInfo,
  type MTLSOptions,
} from '../../core/security/mtls.js';


export type { CertificateHeaders, CertificateInfo, MTLSOptions };




function extractHeadersFromEvent(event: RequestEvent): CertificateHeaders {
  return {
    clientCert:
      event.request.headers.get('X-SSL-Client-Cert') ||
      event.request.headers.get('X-Client-Cert') ||
      event.request.headers.get('X-Forwarded-Client-Cert') ||
      undefined,
    clientSubject:
      event.request.headers.get('X-SSL-Client-S-DN') ||
      event.request.headers.get('X-Client-DN') ||
      undefined,
    clientVerify:
      event.request.headers.get('X-SSL-Client-Verify') ||
      event.request.headers.get('X-Client-Verified') ||
      undefined,
    clientIssuer: event.request.headers.get('X-SSL-Client-I-DN') || undefined,
  };
}




export function extractCertificateFromEvent(
  event: RequestEvent,
  options?: MTLSOptions
): CertificateInfo {
  return coreExtractCertificate(extractHeadersFromEvent(event), {
    validFingerprints: options?.validFingerprints,
  });
}






/**
 * Admit the request only when its forwarded certificate headers pass
 * {@link extractCertificateFromEvent}. There is no host, NODE_ENV or
 * development short-circuit (1.0.0, RP2).
 *
 * Trust model: these checks read headers set by the TLS-terminating proxy and
 * trust them. The proxy must overwrite or strip every client-supplied copy of
 * the certificate headers. Without `validFingerprints`, a forwarded subject
 * with the verify header absent or `NONE` is admitted, so set
 * `validFingerprints` wherever the edge is not guaranteed to strip them.
 */
export function requireMTLS(event: RequestEvent, options?: MTLSOptions): boolean {
  const certInfo = extractCertificateFromEvent(event, options);

  if (!certInfo.isValid) {
    return false;
  }

  (event.locals as unknown as { mTLSCert: CertificateInfo }).mTLSCert = certInfo;
  return true;
}




export function getCertificateFingerprintFromEvent(
  event: RequestEvent,
  options?: MTLSOptions
): string | null {
  return coreGetCertificateFingerprint(extractHeadersFromEvent(event), {
    validFingerprints: options?.validFingerprints,
  });
}
