'use strict';

/**
 * PhantomRipperRMM — auth routes with mandatory TOTP.
 *
 * POST /api/auth/login {username, password}
 *   -> {totp_required: true, ticket}                (user has a secret)
 *   -> {totp_setup: true, ticket, secret, otpauth}  (first login: secret revealed once)
 * POST /api/auth/totp {ticket, code}
 *   -> {token, user}
 */

const express = require('express');
const auth = require('../auth');
const sessions = require('../sessionManager');
const config = require('../config');
const totp = require('../totp');

const router = express.Router();

router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const user = await auth.verifyCredentials(username, password);
  if (!user) {
    await sessions.logEvent('auth', `failed login for ${username}`, 'warn', { ip: req.ip });
    return res.status(401).json({ error: 'invalid credentials' });
  }

  let secret = await auth.getTotpSecret(username);
  if (!secret && config.totpSecret) {
    // enforcement mode: the pre-seeded secret applies to every operator
    secret = config.totpSecret;
    await auth.setTotpSecret(username, secret);
  }
  if (secret && config.totpSecret && secret !== config.totpSecret) {
    // env rotation is authoritative: stored secret follows the configured one
    secret = config.totpSecret;
    await auth.setTotpSecret(username, secret);
  }

  const ticket = auth.issueTotpTicket(username);

  if (!secret) {
    // first login with no enforcement secret: provision and reveal once
    secret = totp.generateSecret();
    await auth.setTotpSecret(username, secret);
    await sessions.logEvent('auth', `TOTP enrolled for ${username}`, 'info', {});
    return res.json({
      totp_setup: true,
      ticket,
      secret,
      otpauth: totp.otpauthUri(secret, username),
    });
  }

  await sessions.logEvent('auth', `password ok for ${username} — awaiting TOTP`, 'info', { ip: req.ip });
  res.json({ totp_required: true, ticket });
});

router.post('/totp', async (req, res) => {
  const { ticket, code } = req.body || {};
  const username = auth.verifyTotpTicket(ticket);
  if (!username) return res.status(401).json({ error: 'login ticket expired — sign in again' });
  if (!code) return res.status(400).json({ error: 'authenticator code required' });

  const secret = await auth.getTotpSecret(username);
  if (!secret) return res.status(400).json({ error: 'no TOTP secret provisioned' });
  if (!totp.verifyToken(secret, code, 1)) {
    await sessions.logEvent('auth', `invalid TOTP for ${username}`, 'warn', { ip: req.ip });
    return res.status(401).json({ error: 'invalid authenticator code' });
  }
  if (!auth.consumeTotpTicket(ticket)) {
    await sessions.logEvent('auth', `replayed TOTP ticket for ${username}`, 'warn', { ip: req.ip });
    return res.status(401).json({ error: 'login ticket expired — sign in again' });
  }

  const store = require('../store');
  const row = await store.get('SELECT * FROM users WHERE username = ?', [username]);
  if (!row) return res.status(401).json({ error: 'user missing' });

  const user = { id: row.id, username: row.username, role: row.role };
  const token = auth.issueToken(user);
  await sessions.logEvent('auth', `login: ${username} (TOTP ok)`, 'info', { ip: req.ip });
  res.json({ token, user });
});

router.get('/me', auth.requireAuth, (req, res) => {
  res.json({ user: req.user });
});

router.post('/users', auth.requireAuth, auth.requireRole('admin'), async (req, res) => {
  const { username, password, role } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const user = await auth.createUser(username, password, role || 'operator');
    await sessions.logEvent('auth', `created user ${username} (${role || 'operator'})`, 'info', { by: req.user.username });
    res.json({ user });
  } catch (err) {
    res.status(409).json({ error: 'user already exists' });
  }
});

module.exports = router;
