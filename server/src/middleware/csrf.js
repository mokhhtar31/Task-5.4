import { doubleCsrf } from 'csrf-csrf';

// Double-submit-cookie pattern:
//   * the server sets a CSRF cookie AND hands the matching token to our own UI
//   * every write must echo that token back in a header
// The attacker's page can make the browser SEND cookies (it always could) but
// can never READ our origin's response to get the token — the same-origin
// policy forbids it. That asymmetry is what closes the hole.
const {
  generateCsrfToken,
  doubleCsrfProtection,
  invalidCsrfTokenError
} = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,

  // Binds the token to this browser's session. '' keeps it working pre-login.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',

  cookieName: 'x-csrf-token',
  cookieOptions: { sameSite: 'lax', secure: false, path: '/' },

  // Safe methods never change state, so they stay exempt.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],

  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'] || req.body?._csrf
});

// Pre-auth routes run before a session exists, so there is no token to require.
const EXEMPT = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

export { generateCsrfToken, invalidCsrfTokenError };
