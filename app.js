const express    = require('express');
const { Pool }   = require('pg');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path       = require('path');

const app = express();

const pool = new Pool({
    user:     'postgres',
    host:     'localhost',
    database: 'authx_db',
    password: 'alexiamaria399',
    port:     5432,
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

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
        return res.status(400).send(page('Eroare', '<div class="alert alert-danger">Username și parola sunt obligatorii.</div><a href="/register">← Înapoi</a>'));
    }

    try {
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
            [username, password, role || 'ANALYST']
        );
        await logAction(result.rows[0].id, 'REGISTER', 'auth', null, req);

        res.send(page('Cont Creat', `
            <div class="alert alert-success">✓ Cont creat cu succes!</div>
            <a href="/login" class="btn btn-primary">→ Mergi la Login</a>
        `));
    } catch (err) {
        if (err.code === '23505') {
            res.status(400).send(page('Eroare', '<div class="alert alert-danger">Utilizatorul există deja.</div><a href="/register">← Încearcă din nou</a>'));
        } else {
            res.status(500).send(page('Eroare Server', `<pre class="bg-light p-3">${err.stack}</pre>`));
        }
    }
});

// -------------------------------------------------------
// 2. LOGIN
// -------------------------------------------------------
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1', [username]
        );

        if (result.rows.length === 0) {
            await logAction(null, 'LOGIN_FAIL_NO_USER', 'auth', null, req);
            return res.status(401).send(page('Login Eșuat', `
                <div class="alert alert-warning">
                    Utilizatorul <strong>${escHtml(username)}</strong> nu există în sistem.
                </div>
                <a href="/login" class="btn btn-secondary">← Înapoi</a>
            `));
        }

        const user = result.rows[0];

        if (user.password_hash !== password) {
            await logAction(user.id, 'LOGIN_FAIL_WRONG_PASS', 'auth', null, req);
            return res.status(401).send(page('Login Eșuat', `
                <div class="alert alert-danger">
                    Parolă greșită pentru utilizatorul <strong>${escHtml(username)}</strong>.
                </div>
                <a href="/login" class="btn btn-secondary">← Înapoi</a>
            `));
        }

        res.cookie('user_id',  String(user.id));
        res.cookie('role',     user.role);
        res.cookie('username', user.email);

        await logAction(user.id, 'LOGIN', 'auth', null, req);
        res.redirect('/dashboard');

    } catch (err) {
        res.status(500).send(page('Eroare', `<pre>${err.message}</pre>`));
    }
});

// -------------------------------------------------------
// 3. LOGOUT
// -------------------------------------------------------
app.get('/logout', async (req, res) => {
    const userId = req.cookies.user_id;
    if (userId) await logAction(userId, 'LOGOUT', 'auth', null, req);
    res.clearCookie('user_id');
    res.clearCookie('role');
    res.clearCookie('username');
    res.redirect('/login');
});

// -------------------------------------------------------
// 4. DASHBOARD
// -------------------------------------------------------
app.get('/dashboard', async (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');

    try {
        const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        const user = userRes.rows[0] || { email: req.cookies.username || '?', role: req.cookies.role || '?', id: userId };

        const ticketsRes = await pool.query(
            'SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id ORDER BY t.created_at DESC'
        );

        const ticketRows = ticketsRes.rows.map(t => `
            <tr>
                <td>${t.id}</td>
                <td><a href="/ticket/${t.id}">${escHtml(t.title)}</a></td>
                <td><span class="badge ${t.severity === 'HIGH' ? 'bg-danger' : t.severity === 'MED' ? 'bg-warning text-dark' : 'bg-success'}">${t.severity}</span></td>
                <td><span class="badge bg-secondary">${t.status}</span></td>
                <td><small>${escHtml(t.owner_email || 'N/A')}</small></td>
                <td>
                    <a href="/ticket/${t.id}" class="btn btn-sm btn-primary py-0">Vezi</a>
                    <a href="/ticket/${t.id}/delete" class="btn btn-sm btn-danger py-0" onclick="return confirm('Șterge?')">Del</a>
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
        <span>Salut, <strong>${escHtml(user.email)}</strong> | Rol: <strong>${escHtml(user.role)}</strong></span>
        ${user.role === 'MANAGER' ? '<a href="/audit" class="btn btn-outline-warning btn-sm">📋 Audit Logs</a>' : ''}
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
</body>
</html>`);
    } catch (err) {
        res.status(500).send(page('Eroare', `<pre>${err.message}</pre>`));
    }
});

// -------------------------------------------------------
// 5. TICKET VIEW
// -------------------------------------------------------
app.get('/ticket/:id', async (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');

    try {
        const result = await pool.query(
            'SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id WHERE t.id = $1',
            [req.params.id]
        );
        if (result.rows.length === 0) return res.status(404).send(page('404', '<div class="alert alert-danger">Ticket negăsit.</div><a href="/dashboard">← Dashboard</a>'));

        const t = result.rows[0];

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
                    <div class="border rounded p-3 bg-light">${t.description || '<em>fără descriere</em>'}</div>
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
                <a href="/ticket/${t.id}/delete" class="btn btn-danger btn-sm" onclick="return confirm('Ștergi ticket-ul #${t.id}?')">🗑 Șterge</a>
            </div>
        `));
    } catch (err) {
        res.status(500).send(page('Eroare', `<pre>${err.message}</pre>`));
    }
});

// -------------------------------------------------------
// 6. TICKET EDIT
// -------------------------------------------------------
app.post('/ticket/:id/edit', async (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');
    const { status } = req.body;
    await pool.query('UPDATE tickets SET status = $1, updated_at = NOW() WHERE id = $2', [status, req.params.id]);
    await logAction(userId, 'UPDATE_TICKET', 'ticket', req.params.id, req);
    res.redirect(`/ticket/${req.params.id}`);
});

// -------------------------------------------------------
// 7. TICKET DELETE
// -------------------------------------------------------
app.get('/ticket/:id/delete', async (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');
    await pool.query('DELETE FROM tickets WHERE id = $1', [req.params.id]);
    await logAction(userId, 'DELETE_TICKET', 'ticket', req.params.id, req);
    res.redirect('/dashboard');
});

// -------------------------------------------------------
// 8. CREATE TICKET
// -------------------------------------------------------
app.post('/tickets', async (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');
    const { title, description, severity } = req.body;
    const result = await pool.query(
        'INSERT INTO tickets (title, description, severity, status, owner_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [title, description || '', severity || 'LOW', 'OPEN', userId]
    );
    await logAction(userId, 'CREATE_TICKET', 'ticket', result.rows[0].id, req);
    res.redirect('/dashboard');
});

// -------------------------------------------------------
// 9. SEARCH
// -------------------------------------------------------
app.get('/search', async (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');
    const q = req.query.q || '';

    const sqlRaw = `SELECT t.*, u.email AS owner_email FROM tickets t LEFT JOIN users u ON t.owner_id = u.id WHERE t.title ILIKE '%${q}%' OR t.description ILIKE '%${q}%'`;

    try {
        const result = await pool.query(sqlRaw);
        const rows = result.rows.map(t =>
            `<tr><td>${t.id}</td><td>${escHtml(t.title)}</td><td>${t.severity}</td><td>${t.status}</td><td>${escHtml(t.owner_email || 'N/A')}</td></tr>`
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
        res.status(500).send(page('Eroare', `<pre>${err.message}</pre>`));
    }
});

// -------------------------------------------------------
// 10. FORGOT PASSWORD
// -------------------------------------------------------
const resetTokens = {};

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const resetToken = String(Date.now()).slice(-5);
    resetTokens[email] = { token: resetToken, used: false };

    res.send(page('Token Trimis', `
        <div class="alert alert-info">
            Token generat pentru <strong>${escHtml(email)}</strong>:<br>
            <span style="font-size:2rem;font-weight:bold;letter-spacing:.3rem">${resetToken}</span>
        </div>
        <a href="/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}" class="btn btn-primary">
            → Resetează parola
        </a>
    `));
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
                </div>
                <button class="btn btn-primary w-100">Resetează</button>
            </form>
        </div>
    `));
});

app.post('/reset-password', async (req, res) => {
    const { token, email, newPassword } = req.body;
    const entry = resetTokens[email];

    if (entry && entry.token === token) {
        await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [newPassword, email]);

        res.send(page('Parolă Resetată', `
            <div class="alert alert-success">✓ Parola a fost resetată cu succes!</div>
            <a href="/login" class="btn btn-primary">→ Login</a>
        `));
    } else {
        res.status(400).send(page('Token Invalid', `
            <div class="alert alert-danger">Token invalid sau expirat.</div>
            <a href="/forgot-password" class="btn btn-secondary">← Încearcă din nou</a>
        `));
    }
});

// -------------------------------------------------------
// 12. AUDIT LOGS
// -------------------------------------------------------
app.get('/audit', async (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) return res.redirect('/login');

    const role = req.cookies.role;
    if (role !== 'MANAGER') {
        return res.status(403).send(page('Acces Interzis', `
            <div class="alert alert-danger">
                403 Forbidden — Rol insuficient: <code>${escHtml(role)}</code>
            </div>
            <a href="/dashboard" class="btn btn-secondary">← Dashboard</a>
        `));
    }

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
        res.status(500).send(page('Eroare', `<pre>${err.message}</pre>`));
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
        .replace(/"/g, '&quot;');
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
    console.log(`AuthX - http://localhost:${PORT}`);
});
