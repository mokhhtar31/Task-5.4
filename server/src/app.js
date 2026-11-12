import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRoutes from './routes/auth.js';
import bookingRoutes from './routes/bookings.js';
import userRoutes from './routes/users.js';
import maintenanceRoutes from './routes/maintenance.js';
import { csrfProtection, generateCsrfToken, invalidCsrfTokenError } from './middleware/csrf.js';
import { globalLimiter } from './middleware/rateLimit.js';

const app = express();

app.use(morgan('dev'));
app.use(cors({
  origin: 'http://localhost:5175',
  credentials: true,
  allowedHeaders: ['Content-Type', 'x-csrf-token']   // let our UI send the token
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());        // MUST precede csrfProtection
app.use(globalLimiter);

app.get('/api/health', (req, res) => res.json({ ok: true }));

// Only our own origin can read this response, so only our UI gets a token.
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

app.use(csrfProtection);

app.use('/api/auth', authRoutes);
app.use('/api/bookings', bookingRoutes);
app.use('/api/users', userRoutes);
app.use('/api/maintenance', maintenanceRoutes);

app.use((req, res) => res.status(404).json({ message: 'Not Found' }));

app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError || err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid or missing CSRF token' });
  }
  console.error(err);
  res.status(err.status || err.statusCode || 500).json({ message: err.message || 'Server Error' });
});

export default app;