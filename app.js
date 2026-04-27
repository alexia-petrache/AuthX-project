const express      = require('express');
const { Pool }     = require('pg');
const bcrypt       = require('bcrypt');
const session      = require('express-session');
const rateLimit    = require('express-rate-limit');
const crypto       = require('crypto');
const path         = require('path');

const app = express();

const pool = new Pool({
    user:     'postgres',
    host:     'localhost',
    database: 'authx_db',
    password: 'alexiamaria399',
    port:     5432,
});

// -------------------------------------------------------
// MIDDLEWARE
// -------------------------------------------------------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'authx-v2-secret-schimba-in-productie',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        maxAge: 30 * 60 * 1000
    }
}));

app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' https://cdn.jsdelivr.net; " +
        "style-src 'self' https://cdn.jsdelivr.net; " +
        "font-src 'self' https://cdn.jsdelivr.net; " +
        "img-src 'self' data:;"
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Rate limiter: max 10 cereri la /login per IP per 15 minute
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Prea multe încercări. Încearcă din nou după 15 minute.',
    standardHeaders: true,
    legacyHeaders: false,
});

// -------------------------------------------------------
// AUTH MIDDLEWARE
// -------------------------------------------------------
function requireAuth(req, res, next) {
    if (!req.session.userId) return res.redirect('/login');
    next();
}

function requireRole(role) {
    return (req, res, next) => {
        if (req.session.role !== role) {
            return res.status(403).send(page('Acces Interzis',
                '<div class="alert alert-danger">403 Forbidden — Rol insuficient.</div>' +
                '<a href="/dashboard" class="btn btn-secondary">← Dashboard</a>'
            ));
        }
        next();
    };
}

// -------------------------------------------------------
// AUDIT HELPER
// -------------------------------------------------------
async function logAction(userId, action, resource, resourceId, req) {
    try {
        await pool.query(
            'INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES ($1, $2, $3, $4, $5)',
            [userId || null, action, resource, resourceId ? String(resourceId) : null, req.ip]
        );
    } catch (err) {
        console.error('[Audit Error]', err.message);
    }
}

// -------------------------------------------------------
// VALIDARE PAROLA
// -------------------------------------------------------
function validatePassword(password) {
    if (!password || password.length < 8) {
        return 'Parola trebuie să aibă cel puțin 8 caractere.';
    }
    if (!/[A-Z]/.test(password)) {
        return 'Parola trebuie să conțină cel puțin o literă mare.';
    }
    if (!/[0-9]/.test(password)) {
        return 'Parola trebuie să conțină cel puțin o cifră.';
    }
    if (!/[!@#$%^&*()_+\-=\[\]{}]/.test(password)) {
        return 'Parola trebuie să conțină cel puțin un caracter special (!@#$%^&*).';
    }
    return null;
}

// -------------------------------------------------------
// PAGINI STATICE
// -------------------------------------------------------
app.get('/',                (req, res) => res.redirect('/login'));
app.get('/login',           (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register',        (req, res) => res.sendFile(path.join(__dirname, 'public', 'inregistrare.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot_pasword.html')));

// -------------------------------------------------------
// 1. REGISTER
// -------------------------------------------------------
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password) {
        return res.status(400).send(page('Eroare',
            '<div class="alert alert-danger">Email și parola sunt obligatorii.</div>' +
            '<a href="/register">← Înapoi</a>'
        ));
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(username)) {
        return res.status(400).send(page('Eroare',
            '<div class="alert alert-danger">Format email invalid.</div>' +
            '<a href="/register">← Înapoi</a>'
        ));
    }

    const pwError = validatePassword(password);
    if (pwError) {
        return res.status(400).send(page('Eroare',
            `<div class="alert alert-danger">${escHtml(pwError)}</div>` +
            '<a href="/register">← Înapoi</a>'
        ));
    }

    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const allowedRole = (role === 'MANAGER') ? 'MANAGER' : 'ANALYST';

        const result = await pool.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
            [username, passwordHash, allowedRole]
        );
        await logAction(result.rows[0].id, 'REGISTER', 'auth', null, req);

        res.send(page('Cont Creat',
            '<div class="alert alert-success">✓ Cont creat cu succes!</div>' +
            '<a href="/login" class="btn btn-primary">→ Mergi la Login</a>'
        ));
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).send(page('Eroare',
                '<div class="alert alert-danger">Utilizatorul există deja.</div>' +
                '<a href="/register">← Încearcă din nou</a>'
            ));
        }
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// 2. LOGIN
// -------------------------------------------------------
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const genericError = page('Login Eșuat',
        '<div class="alert alert-danger">Credențiale incorecte.</div>' +
        '<a href="/login" class="btn btn-secondary">← Înapoi</a>'
    );

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1', [username]
        );

        if (result.rows.length === 0) {
            await bcrypt.compare(password, '$2b$12$invalidhashfortimingattackprevention00000000000000000000');
            await logAction(null, 'LOGIN_FAIL', 'auth', null, req);
            return res.status(401).send(genericError);
        }

        const user = result.rows[0];

        if (user.locked_until && new Date() < new Date(user.locked_until)) {
            return res.status(401).send(page('Cont Blocat',
                '<div class="alert alert-danger">Contul este temporar blocat. Încearcă din nou mai târziu.</div>' +
                '<a href="/login" class="btn btn-secondary">← Înapoi</a>'
            ));
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            const newAttempts = (user.login_attempts || 0) + 1;
            if (newAttempts >= 5) {
                await pool.query(
                    "UPDATE users SET login_attempts = $1, locked_until = NOW() + INTERVAL '15 minutes' WHERE id = $2",
                    [newAttempts, user.id]
                );
            } else {
                await pool.query(
                    'UPDATE users SET login_attempts = $1 WHERE id = $2',
                    [newAttempts, user.id]
                );
            }
            await logAction(user.id, 'LOGIN_FAIL', 'auth', null, req);
            return res.status(401).send(genericError);
        }

        await pool.query(
            'UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = $1',
            [user.id]
        );

        req.session.regenerate((err) => {
            if (err) return res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
            req.session.userId = user.id;
            req.session.role   = user.role;
            req.session.email  = user.email;
            logAction(user.id, 'LOGIN', 'auth', null, req);
            res.redirect('/dashboard');
        });

    } catch (err) {
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// 3. LOGOUT
// -------------------------------------------------------
app.get('/logout', async (req, res) => {
    const userId = req.session.userId;
    if (userId) await logAction(userId, 'LOGOUT', 'auth', null, req);
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// -------------------------------------------------------
// 4. DASHBOARD
// -------------------------------------------------------
app.get('/dashboard', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const role   = req.session.role;
    const email  = req.session.email;

    try {
        let ticketsRes;
        if (role === 'MANAGER') {
            ticketsRes = await pool.query(
                'SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id ORDER BY t.created_at DESC'
            );
        } else {
            ticketsRes = await pool.query(
                'SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id WHERE t.owner_id = $1 ORDER BY t.created_at DESC',
                [userId]
            );
        }

        const ticketRows = ticketsRes.rows.map(t => `
            <tr>
                <td>${t.id}</td>
                <td><a href="/ticket/${t.id}">${escHtml(t.title)}</a></td>
                <td><span class="badge ${t.severity === 'HIGH' ? 'bg-danger' : t.severity === 'MED' ? 'bg-warning text-dark' : 'bg-success'}">${t.severity}</span></td>
                <td><span class="badge bg-secondary">${t.status}</span></td>
                <td><small>${escHtml(t.owner_email || 'N/A')}</small></td>
                <td>
                    <a href="/ticket/${t.id}" class="btn btn-sm btn-primary py-0">Vezi</a>
                    <a href="/ticket/${t.id}/delete" class="btn btn-sm btn-danger py-0 btn-delete">Șterge</a>
                </td>
            </tr>`).join('') || '<tr><td colspan="6" class="text-center text-muted">Niciun ticket. Adaugă primul!</td></tr>';

        res.send(`<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>AuthX – Dashboard</title>
</head>
<body>
<nav class="navbar navbar-dark bg-dark px-4">
    <span class="navbar-brand fw-bold">🔐 AuthX Internal Portal</span>
    <div class="d-flex align-items-center text-white gap-3">
        <span>Salut, <strong>${escHtml(email)}</strong> | Rol: <strong>${escHtml(role)}</strong></span>
        ${role === 'MANAGER' ? '<a href="/audit" class="btn btn-outline-warning btn-sm">📋 Audit Logs</a>' : ''}
        <a href="/logout" class="btn btn-outline-danger btn-sm">Logout</a>
    </div>
</nav>
<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-2">
        <h5 class="mb-0">Tickete de Securitate</h5>
        <div class="d-flex gap-2">
            <form class="d-flex" action="/search" method="GET">
                <input type="text" name="q" class="form-control form-control-sm" placeholder="Caută...">
                <button class="btn btn-sm btn-outline-dark ms-1">🔍</button>
            </form>
            <button class="btn btn-sm btn-success" data-bs-toggle="modal" data-bs-target="#addModal">+ Adaugă Ticket</button>
        </div>
    </div>
    <table class="table table-hover shadow-sm">
        <thead class="table-dark">
            <tr><th>ID</th><th>Titlu</th><th>Sev.</th><th>Status</th><th>Owner</th><th>Acțiuni</th></tr>
        </thead>
        <tbody>${ticketRows}</tbody>
    </table>
</div>

<div class="modal fade" id="addModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-success text-white">
                <h5 class="modal-title">Ticket Nou</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
            </div>
            <form action="/tickets" method="POST">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label">Titlu</label>
                        <input type="text" name="title" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Descriere</label>
                        <textarea name="description" class="form-control" rows="3"></textarea>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Severitate</label>
                        <select name="severity" class="form-select">
                            <option value="HIGH">HIGH</option>
                            <option value="MED">MED</option>
                            <option value="LOW">LOW</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Anulează</button>
                    <button type="submit" class="btn btn-success">Salvează</button>
                </div>
            </form>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="/dashboard-v2.js"></script>
</body>
</html>`);
    } catch (err) {
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// 5. TICKET VIEW
// -------------------------------------------------------
app.get('/ticket/:id', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const role   = req.session.role;

    try {
        const result = await pool.query(
            'SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id WHERE t.id = $1',
            [req.params.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).send(page('404',
                '<div class="alert alert-danger">Ticket negăsit.</div>' +
                '<a href="/dashboard">← Dashboard</a>'
            ));
        }

        const t = result.rows[0];

        if (role !== 'MANAGER' && t.owner_id !== userId) {
            await logAction(userId, 'ACCESS_DENIED', 'ticket', t.id, req);
            return res.status(403).send(page('Acces Interzis',
                '<div class="alert alert-danger">Nu ai acces la acest ticket.</div>' +
                '<a href="/dashboard">← Dashboard</a>'
            ));
        }

        res.send(page(`Ticket #${t.id}`, `
            <div class="card">
                <div class="card-header d-flex justify-content-between">
                    <h5 class="mb-0">${escHtml(t.title)}</h5>
                    <div>
                        <span class="badge ${t.severity === 'HIGH' ? 'bg-danger' : t.severity === 'MED' ? 'bg-warning text-dark' : 'bg-success'}">${t.severity}</span>
                        <span class="badge bg-primary ms-1">${t.status}</span>
                    </div>
                </div>
                <div class="card-body">
                    <p class="text-muted small">Owner: ${escHtml(t.owner_email || 'N/A')} | Creat: ${new Date(t.created_at).toLocaleString('ro-RO')}</p>
                    <hr>
                    <p><strong>Descriere:</strong></p>
                    <div class="border rounded p-3 bg-light">${escHtml(t.description || '')}</div>
                </div>
            </div>
            <form action="/ticket/${t.id}/edit" method="POST" class="mt-3 d-flex gap-2 align-items-end">
                <div>
                    <label class="form-label mb-1">Actualizează Status:</label>
                    <select name="status" class="form-select form-select-sm">
                        <option ${t.status === 'OPEN' ? 'selected' : ''}>OPEN</option>
                        <option value="IN PROGRESS" ${t.status === 'IN PROGRESS' ? 'selected' : ''}>IN PROGRESS</option>
                        <option ${t.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
                    </select>
                </div>
                <button class="btn btn-warning btn-sm">Actualizează</button>
            </form>
            <div class="mt-3 d-flex gap-2">
                <a href="/dashboard" class="btn btn-secondary btn-sm">← Dashboard</a>
                <a href="/ticket/${t.id}/delete" class="btn btn-danger btn-sm btn-delete-single">🗑 Șterge</a>
            </div>
            <script src="/confirm-delete.js"></script>
        `));
    } catch (err) {
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// 6. TICKET EDIT
// -------------------------------------------------------
app.post('/ticket/:id/edit', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const role   = req.session.role;

    const result = await pool.query('SELECT owner_id FROM tickets WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).send(page('404', '<div class="alert alert-danger">Ticket negăsit.</div>'));

    if (role !== 'MANAGER' && result.rows[0].owner_id !== userId) {
        return res.status(403).send(page('Acces Interzis', '<div class="alert alert-danger">Nu ai acces la acest ticket.</div>'));
    }

    const { status } = req.body;
    const allowed = ['OPEN', 'IN PROGRESS', 'RESOLVED'];
    if (!allowed.includes(status)) {
        return res.status(400).send(page('Eroare', '<div class="alert alert-danger">Status invalid.</div>'));
    }

    await pool.query('UPDATE tickets SET status = $1, updated_at = NOW() WHERE id = $2', [status, req.params.id]);
    await logAction(userId, 'UPDATE_TICKET', 'ticket', req.params.id, req);
    res.redirect(`/ticket/${req.params.id}`);
});

// -------------------------------------------------------
// 7. TICKET DELETE
// -------------------------------------------------------
app.get('/ticket/:id/delete', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const role   = req.session.role;

    const result = await pool.query('SELECT owner_id FROM tickets WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.redirect('/dashboard');

    if (role !== 'MANAGER' && result.rows[0].owner_id !== userId) {
        return res.status(403).send(page('Acces Interzis', '<div class="alert alert-danger">Nu ai acces la acest ticket.</div>'));
    }

    await pool.query('DELETE FROM tickets WHERE id = $1', [req.params.id]);
    await logAction(userId, 'DELETE_TICKET', 'ticket', req.params.id, req);
    res.redirect('/dashboard');
});

// -------------------------------------------------------
// 8. CREATE TICKET
// -------------------------------------------------------
app.post('/tickets', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const { title, description, severity } = req.body;

    if (!title || title.trim().length === 0) {
        return res.status(400).send(page('Eroare', '<div class="alert alert-danger">Titlul este obligatoriu.</div>'));
    }

    const allowedSeverity = ['HIGH', 'MED', 'LOW'];
    const safeSeverity = allowedSeverity.includes(severity) ? severity : 'LOW';

    const result = await pool.query(
        'INSERT INTO tickets (title, description, severity, status, owner_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [title.trim(), description || '', safeSeverity, 'OPEN', userId]
    );
    await logAction(userId, 'CREATE_TICKET', 'ticket', result.rows[0].id, req);
    res.redirect('/dashboard');
});

// -------------------------------------------------------
// 9. SEARCH — query parametrizat (fara SQL injection)
// -------------------------------------------------------
app.get('/search', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const role   = req.session.role;
    const q      = req.query.q || '';

    try {
        let result;
        if (role === 'MANAGER') {
            result = await pool.query(
                'SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id WHERE t.title ILIKE $1 OR t.description ILIKE $1 ORDER BY t.created_at DESC',
                [`%${q}%`]
            );
        } else {
            result = await pool.query(
                'SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id WHERE (t.title ILIKE $1 OR t.description ILIKE $1) AND t.owner_id = $2 ORDER BY t.created_at DESC',
                [`%${q}%`, userId]
            );
        }

        const rows = result.rows.map(t =>
            `<tr>
                <td>${t.id}</td>
                <td><a href="/ticket/${t.id}">${escHtml(t.title)}</a></td>
                <td>${t.severity}</td>
                <td>${t.status}</td>
                <td>${escHtml(t.owner_email || 'N/A')}</td>
            </tr>`
        ).join('') || '<tr><td colspan="5" class="text-muted text-center">Niciun rezultat.</td></tr>';

        res.send(page('Rezultate căutare', `
            <h5>Rezultate pentru: <em>"${escHtml(q)}"</em> (${result.rows.length} rânduri)</h5>
            <table class="table table-sm table-hover">
                <thead class="table-dark"><tr><th>ID</th><th>Titlu</th><th>Sev.</th><th>Status</th><th>Owner</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
            <a href="/dashboard" class="btn btn-secondary btn-sm">← Dashboard</a>
        `));
    } catch (err) {
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// 10. FORGOT PASSWORD
// -------------------------------------------------------
const RESET_EXPIRY_MS = 15 * 60 * 1000;

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const genericMsg = page('Token Trimis',
        '<div class="alert alert-info">Dacă adresa există în sistem, vei primi un token de resetare.</div>' +
        '<a href="/login" class="btn btn-secondary">← Login</a>'
    );

    try {
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.send(genericMsg);
        }

        const userId = result.rows[0].id;

        await pool.query(
            'UPDATE reset_tokens SET used = TRUE WHERE user_id = $1 AND used = FALSE',
            [userId]
        );

        const token     = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expiresAt = new Date(Date.now() + RESET_EXPIRY_MS);

        await pool.query(
            'INSERT INTO reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
            [userId, tokenHash, expiresAt]
        );

        await logAction(userId, 'FORGOT_PASSWORD', 'auth', null, req);

        res.send(page('Token Trimis', `
            <div class="alert alert-info">
                Token de resetare (valabil 15 minute):<br>
                <small class="text-muted">În producție acesta ar fi trimis pe email.</small>
            </div>
            <a href="/reset-password?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}" class="btn btn-primary mt-2">
                → Resetează parola
            </a>
        `));
    } catch (err) {
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// 11. RESET PASSWORD
// -------------------------------------------------------
app.get('/reset-password', (req, res) => {
    const { token, email } = req.query;
    res.send(page('Resetare Parolă', `
        <div class="col-md-5 mx-auto">
            <form action="/reset-password" method="POST" class="card p-4 shadow">
                <h5 class="mb-3">Parolă Nouă</h5>
                <input type="hidden" name="token" value="${escHtml(token || '')}">
                <input type="hidden" name="email" value="${escHtml(email || '')}">
                <div class="mb-3">
                    <label class="form-label">Parolă nouă</label>
                    <input type="password" name="newPassword" class="form-control" required>
                    <div class="form-text">Min. 8 caractere, o literă mare, o cifră, un caracter special.</div>
                </div>
                <button class="btn btn-primary w-100">Resetează</button>
            </form>
        </div>
    `));
});

app.post('/reset-password', async (req, res) => {
    const { token, email, newPassword } = req.body;

    const pwError = validatePassword(newPassword);
    if (pwError) {
        return res.status(400).send(page('Eroare',
            `<div class="alert alert-danger">${escHtml(pwError)}</div>` +
            '<a href="/forgot-password">← Încearcă din nou</a>'
        ));
    }

    const tokenHash = crypto.createHash('sha256').update(token || '').digest('hex');

    try {
        const result = await pool.query(
            `SELECT rt.id, rt.user_id FROM reset_tokens rt
             JOIN users u ON rt.user_id = u.id
             WHERE u.email = $1
               AND rt.token_hash = $2
               AND rt.used = FALSE
               AND rt.expires_at > NOW()`,
            [email, tokenHash]
        );

        if (result.rows.length === 0) {
            return res.status(400).send(page('Token Invalid',
                '<div class="alert alert-danger">Token invalid sau expirat.</div>' +
                '<a href="/forgot-password" class="btn btn-secondary">← Încearcă din nou</a>'
            ));
        }

        const { id: tokenId, user_id: userId } = result.rows[0];
        const hash = await bcrypt.hash(newPassword, 12);

        await pool.query(
            'UPDATE users SET password_hash = $1, login_attempts = 0, locked_until = NULL WHERE id = $2',
            [hash, userId]
        );
        await pool.query('UPDATE reset_tokens SET used = TRUE WHERE id = $1', [tokenId]);
        await logAction(userId, 'RESET_PASSWORD', 'auth', null, req);

        res.send(page('Parolă Resetată',
            '<div class="alert alert-success">✓ Parola a fost resetată cu succes!</div>' +
            '<a href="/login" class="btn btn-primary">→ Login</a>'
        ));
    } catch (err) {
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// 12. AUDIT LOGS
// -------------------------------------------------------
app.get('/audit', requireAuth, requireRole('MANAGER'), async (req, res) => {
    try {
        const logs = await pool.query(
            'SELECT al.*, u.email FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id ORDER BY al.timestamp DESC LIMIT 100'
        );
        const rows = logs.rows.map(l => `
            <tr>
                <td>${l.id}</td>
                <td>${escHtml(l.email || 'N/A')}</td>
                <td><code>${l.action}</code></td>
                <td>${l.resource || '-'}</td>
                <td>${l.resource_id || '-'}</td>
                <td>${escHtml(l.ip_address || '-')}</td>
                <td><small>${new Date(l.timestamp).toLocaleString('ro-RO')}</small></td>
            </tr>`).join('') || '<tr><td colspan="7" class="text-muted text-center">Nicio înregistrare.</td></tr>';

        res.send(page('Audit Logs', `
            <h5>Audit Logs (ultimele 100)</h5>
            <table class="table table-sm table-striped table-hover">
                <thead class="table-dark">
                    <tr><th>ID</th><th>User</th><th>Acțiune</th><th>Resursă</th><th>Res. ID</th><th>IP</th><th>Timestamp</th></tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
            <a href="/dashboard" class="btn btn-secondary btn-sm">← Dashboard</a>
        `));
    } catch (err) {
        res.status(500).send(page('Eroare', '<div class="alert alert-danger">Eroare internă.</div>'));
    }
});

// -------------------------------------------------------
// HELPERS
// -------------------------------------------------------
function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function page(title, body) {
    return `<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>AuthX – ${title}</title>
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-dark px-4 mb-4">
    <span class="navbar-brand fw-bold">🔐 AuthX</span>
    <div class="d-flex gap-2">
        <a href="/dashboard" class="btn btn-outline-light btn-sm">Dashboard</a>
        <a href="/logout" class="btn btn-outline-danger btn-sm">Logout</a>
    </div>
</nav>
<div class="container">
    <h4 class="mb-3">${title}</h4>
    ${body}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`;
}

// -------------------------------------------------------
// START SERVER
// -------------------------------------------------------
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`AuthX v2 (securizata) - http://localhost:${PORT}`);
});
