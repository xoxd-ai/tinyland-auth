







import type { Cookies } from '@sveltejs/kit';
import type { Session, SessionConfig } from '../../types/index.js';

export interface CookieConfig {
  
  sessionCookieName: string;
  
  authDataCookieName: string;
  
  secure: boolean;
  
  path: string;
  
  sameSite: 'strict' | 'lax' | 'none';
  
  maxAge: number;
}

export const DEFAULT_COOKIE_CONFIG: CookieConfig = {
  sessionCookieName: 'sessionId',
  authDataCookieName: 'authData',
  // Fail closed: only an explicit development or test NODE_ENV drops Secure.
  // An unset NODE_ENV (adapter-node default) still sets it.
  secure: process.env.NODE_ENV !== 'development' && process.env.NODE_ENV !== 'test',
  path: '/',
  sameSite: 'lax',
  maxAge: 60 * 60 * 24 * 7, 
};




export function setSessionCookie(
  cookies: Cookies,
  sessionId: string,
  config: Partial<CookieConfig> = {}
): void {
  const cfg = { ...DEFAULT_COOKIE_CONFIG, ...config };

  cookies.set(cfg.sessionCookieName, sessionId, {
    path: cfg.path,
    httpOnly: true,
    secure: cfg.secure,
    sameSite: cfg.sameSite,
    maxAge: cfg.maxAge,
  });
}






export function setAuthDataCookie(
  cookies: Cookies,
  session: Session,
  config: Partial<CookieConfig> = {}
): void {
  const cfg = { ...DEFAULT_COOKIE_CONFIG, ...config };

  const authData = JSON.stringify({
    sessionId: session.id,
    user: session.user,
    expires: session.expires,
  });

  cookies.set(cfg.authDataCookieName, authData, {
    path: cfg.path,
    httpOnly: false, 
    secure: cfg.secure,
    sameSite: 'lax',
    maxAge: cfg.maxAge,
  });
}




export function clearSessionCookies(
  cookies: Cookies,
  config: Partial<CookieConfig> = {}
): void {
  const cfg = { ...DEFAULT_COOKIE_CONFIG, ...config };

  cookies.delete(cfg.sessionCookieName, { path: cfg.path });
  cookies.delete(cfg.authDataCookieName, { path: cfg.path });

  
  cookies.delete('admin_totp_handle', { path: '/admin' });
}




export function getSessionIdFromCookies(
  cookies: Cookies,
  cookieName: string = DEFAULT_COOKIE_CONFIG.sessionCookieName
): string | undefined {
  return cookies.get(cookieName);
}




export function sessionConfigToCookieConfig(sessionConfig: SessionConfig): CookieConfig {
  return {
    sessionCookieName: sessionConfig.cookieName,
    authDataCookieName: 'authData',
    secure: sessionConfig.secureCookie,
    path: '/',
    sameSite: sessionConfig.sameSite,
    maxAge: sessionConfig.maxAge / 1000, 
  };
}
