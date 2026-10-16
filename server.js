// Entry point: node server.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

// Fail fast if configuration is missing
['MONGODB_URI', 'JWT_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH'].forEach((key) => {
  if (!process.env[key]) { console.error(`Missing ${key} in .env`); process.exit(1); }
});

const app = express();
// app.set('trust proxy', 1); // enable when behind Nginx / a hosting proxy so rate limits see real IPs

// CSP is off here because the page loads Tailwind from a CDN and uses inline scripts.
// Tighten it if you later self-host those assets.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: (process.env.CLIENT_ORIGIN || '').split(',').filter(Boolean) }));
app.use(express.json({ limit: '10kb' }));

// Slow down password guessing: 20 auth requests per IP per 15 minutes
app.use('/api/auth', rateLimit({
  windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { message: 'Too many attempts. Try again in a few minutes.' }
}));
app.use('/api/auth', require('./routes/auth'));

// Serve the website from /public (put index.html there for same-origin, CORS-free use)
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', (req, res) => res.status(404).json({ message: 'Not found.' }));

// Central error handler: log details, return nothing sensitive
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error(err);
  res.status(500).json({ message: 'Server error. Please try again later.' });
});

connectDB().then(() => {
  const port = process.env.PORT || 5000;
  app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
});
