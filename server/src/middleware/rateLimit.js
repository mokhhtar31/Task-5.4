import rateLimit from 'express-rate-limit';

// DoS fix: cap how often ONE client may hit the feature. Past the cap the
// request is refused with 429 before it ever reaches the database.
export const maintenanceLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,                 // must be < 40: the test fires 40 and wants both 200 and 429
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' }
});

export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 1000,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' }
});