require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mime = require('mime-types');

const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || 'a_very_insecure_default_secret_for_development';

// --- 1. Database Setup ---
const db = new sqlite3.Database('./file-share.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) return console.error(err.message);
    console.log('✅ Connected to the SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', last_login_ip TEXT, last_fingerprint TEXT, ban_reason TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, owner TEXT NOT NULL, originalName TEXT NOT NULL, storedName TEXT NOT NULL, size INTEGER, embed_type TEXT NOT NULL DEFAULT 'card')`);
    db.run(`CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY NOT NULL, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS banned_fingerprints (fingerprint TEXT PRIMARY KEY NOT NULL, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
});

// --- 2. Security & Core Middleware ---
app.set('trust proxy', 1);
app.use(helmet());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

function generateFingerprint(req) {
    const userAgent = req.headers['user-agent'] || '';
    const acceptLanguage = req.headers['accept-language'] || '';
    const fingerprintString = `${userAgent}${acceptLanguage}`;
    return crypto.createHash('sha256').update(fingerprintString).digest('hex');
}

app.use((req, res, next) => {
    const userIp = req.ip;
    const fingerprint = generateFingerprint(req);
    db.get('SELECT ip FROM banned_ips WHERE ip = ?', [userIp], (err, ipRow) => {
        if (err) return next();
        if (ipRow) {
            const bodyContent = `<main class="text-center"><h1 class="page-title" style="text-align:center;">Access Denied</h1><p>Your IP address has been banned.</p></main>`;
            return renderPage(res, bodyContent, { title: 'Access Denied' });
        }
        db.get('SELECT fingerprint FROM banned_fingerprints WHERE fingerprint = ?', [fingerprint], (err, fpRow) => {
            if (err) return next();
            if (fpRow) {
                const bodyContent = `<main class="text-center"><h1 class="page-title" style="text-align:center;">Access Denied</h1><p>Your device has been banned.</p></main>`;
                return renderPage(res, bodyContent, { title: 'Access Denied' });
            }
            next();
        });
    });
});

app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'strict' } }));
app.use((req, res, next) => {
    res.locals.user = req.session.user;
    if (req.session.flash) { res.locals.flash = req.session.flash; delete req.session.flash; }
    next();
});

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, UPLOAD_DIR),
        filename: (req, file, cb) => {
            const uniquePrefix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            const cleanFilename = file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '');
            cb(null, uniquePrefix + '-' + cleanFilename);
        }
    }),
    limits: { fileSize: 500 * 1024 * 1024 }
});

// --- 3. Helper Functions & Middleware ---
function formatBytes(bytes, decimals = 2) { if (!+bytes) return '0 Bytes'; const k = 1024; const dm = decimals < 0 ? 0 : decimals; const sizes = ["Bytes", "KB", "MB", "GB", "TB"]; const i = Math.floor(Math.log(bytes) / Math.log(k)); return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`; }
const isAuthenticated = (req, res, next) => { if (!req.session.user) return res.redirect('/login'); next(); };
const isAdmin = (req, res, next) => { if (req.session.user && req.session.user.role === 'admin') return next(); res.status(403).send('<h1>403 Forbidden</h1>'); };

// --- 4. Page Rendering ---
function renderPage(res, bodyContent, options = {}) {
    const authLinks = res.locals.user ? `
        ${res.locals.user.role === 'admin' ? '<a href="/admin" class="nav-link">Admin Panel</a>' : ''}
        <a href="/my-files" class="nav-link">My Files</a>
        <a href="/logout" class="nav-link">Logout</a>
    ` : `
        <a href="/login" class="nav-link">Login</a>
        <a href="/register" class="nav-link">Register</a>
    `;

    res.send(`
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${options.title || 'The Vault'}</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root { --primary-purple: #a855f7; --glow-purple: rgba(168, 85, 247, 0.5); --text-primary: #e5e7eb; --text-secondary: #9ca3af; --glass-bg: rgba(255, 255, 255, 0.05); --glass-border: rgba(255, 255, 255, 0.1); --danger-color: #f43f5e; --danger-glow: rgba(244, 63, 94, 0.5); --success-color: #28a745; --success-glow: rgba(40, 167, 69, 0.5); }
            *, *::before, *::after { box-sizing: border-box; }
            @keyframes rotate { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            body { font-family: 'Inter', sans-serif; margin: 0; padding: 40px 20px; background-color: #030712; color: var(--text-primary); overflow-x: hidden; position: relative; min-height: 100vh; }
            body::before { content: ''; position: absolute; width: 600px; height: 600px; filter: blur(150px); background-image: linear-gradient(45deg, #7c3aed, #db2777); top: -150px; left: -150px; animation: rotate 20s cubic-bezier(0.8, 0.2, 0.2, 0.8) alternate infinite; border-radius: 9999px; z-index: -1; }
            .container { max-width: 800px; margin: 0 auto; z-index: 1; position: relative; }
            .glass-panel { background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 16px; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37); }
            .page-title { font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #ec4899, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; text-align: left; margin-bottom: 40px; }
            .section-header { font-size: 1.5rem; font-weight: 600; margin-bottom: 20px; color: var(--primary-purple); }
            .file-list { list-style-type: none; padding: 0; display: flex; flex-direction: column; gap: 15px; }
            .file-item { display: flex; flex-direction: column; gap: 15px; background: linear-gradient(135deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.02)); border-radius: 12px; padding: 20px; border: 1px solid var(--glass-border);}
            .file-main-content { display: flex; align-items: center; gap: 20px; }
            .file-details { flex-grow: 1; }
            .file-name { display: block; font-size: 1.1rem; font-weight: 600; color: var(--text-primary); margin-bottom: 4px; }
            .file-description { font-size: 0.9rem; color: var(--text-secondary); }
            .file-actions { display: flex; gap: 10px; margin-left: auto; align-items: center; }
            .file-size { color: var(--text-secondary); font-size: 0.9rem; white-space: nowrap; }
            .btn { text-decoration: none; display: inline-flex; align-items: center; justify-content: center; color: white; font-weight: 500; padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; transition: all 0.2s ease; white-space: nowrap; font-family: 'Inter', sans-serif; font-size: 1rem; }
            .btn-primary { background-color: var(--primary-purple); } .btn-primary:hover { background-color: #9333ea; box-shadow: 0 0 20px var(--glow-purple); }
            .btn-secondary { background-color: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255,255,255,0.1); } .btn-secondary:hover { background-color: var(--primary-purple); }
            .btn-danger { background-color: var(--danger-color); } .btn-danger:hover { background-color: #be123c; box-shadow: 0 0 20px var(--danger-glow); }
            .btn-success { background-color: var(--success-color); } .btn-success:hover { background-color: #166534; box-shadow: 0 0 20px var(--success-glow); }
            footer { text-align: center; margin-top: 60px; padding-top: 20px; color: var(--text-secondary); font-size: 0.9rem; }
            .navbar { display: flex; justify-content: center; align-items: center; gap: 20px; margin-bottom: 40px; padding: 15px; }
            .nav-link { color: var(--text-secondary); text-decoration: none; font-weight: 500; transition: color 0.2s; } .nav-link:hover { color: var(--primary-purple); }
            form { display: flex; flex-direction: column; gap: 15px; margin: 30px 0; padding: 25px; }
            .text-center { text-align: center; }
            input[type="text"], input[type="password"] { background-color: var(--glass-bg); color: var(--text-primary); border: 1px solid var(--glass-border); padding: 12px; border-radius: 8px; font-size: 1em; transition: all 0.2s ease; backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px); }
            .input-error { border-color: var(--danger-color) !important; box-shadow: 0 0 10px 1px var(--danger-glow) !important; }
            .error-message { color: var(--danger-color); font-size: 0.9rem; margin-top: -5px; text-align: left; }
            .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); display: none; align-items: center; justify-content: center; z-index: 1000; }
            .modal-content { padding: 30px; width: 90%; max-width: 500px; }
            .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
        </style>
        </head><body>
            <div class="container">
                <nav class="navbar glass-panel">${authLinks}</nav>
                ${bodyContent}
                <footer><p>&copy; ${new Date().getFullYear()} The Vault. All rights reserved.</p></footer>
            </div>
            <div id="ban-modal" class="modal-overlay">
                <div class="modal-content glass-panel">
                    <h3>Provide Ban Reason</h3>
                    <form id="ban-reason-form" method="post" action="/admin/users/status" style="margin: 0; padding: 0; background: none; box-shadow: none; border-radius: 0;">
                        <input type="text" id="ban-reason-input" name="reason" placeholder="Reason for ban (e.g., spamming)" required>
                        <input type="hidden" id="ban-username-input" name="username">
                        <input type="hidden" name="action" value="ban">
                        <div class="modal-actions">
                            <button type="button" id="cancel-ban-btn" class="btn btn-secondary">Cancel</button>
                            <button type="submit" class="btn btn-danger">Confirm Ban</button>
                        </div>
                    </form>
                </div>
            </div>
            <script>
                document.addEventListener('DOMContentLoaded', () => {
                    document.body.addEventListener('click', event => {
                        if (event.target.classList.contains('open-ban-modal')) {
                            event.preventDefault();
                            const banModal = document.getElementById('ban-modal');
                            const banUsernameInput = document.getElementById('ban-username-input');
                            if (banModal && banUsernameInput) {
                                const username = event.target.dataset.username;
                                banUsernameInput.value = username;
                                banModal.style.display = 'flex';
                            }
                        }
                    });
                    const banModal = document.getElementById('ban-modal');
                    if (banModal) {
                        const cancelBanBtn = document.getElementById('cancel-ban-btn');
                        if (cancelBanBtn) {
                            cancelBanBtn.addEventListener('click', () => {
                                banModal.style.display = 'none';
                            });
                        }
                        banModal.addEventListener('click', function(event) {
                            if (event.target === banModal) {
                                banModal.style.display = 'none';
                            }
                        });
                    }
                });
            </script>
        </body></html>`);
}

// --- 5. Main Routes ---
app.get('/', (req, res) => {
    const bodyContent = `<main class="text-center"><h1 class="page-title" style="text-align:center;">The Vault</h1><p>Your personal corner of the cloud, secured and styled.</p><p style="margin-top: 40px;">${req.session.user ? '<a href="/my-files" class="btn btn-primary">Enter My Vault</a>' : '<a href="/login" class="btn btn-primary">Login to Enter</a>'}</p></main>`;
    renderPage(res, bodyContent);
});

app.get('/my-files', isAuthenticated, (req, res) => {
    db.all('SELECT * FROM files WHERE owner = ? ORDER BY originalName ASC', [req.session.user.username], (err, userFiles) => {
        if (err) return res.status(500).send("Database error.");
        const fileListHtml = `...`; // Unchanged
        const uploadForm = `...`; // Unchanged
        renderPage(res, `<main><h1 class="page-title">My Vault</h1>${fileListHtml}${uploadForm}</main>`);
    });
});

app.post('/upload', isAuthenticated, upload.single('sharedFile'), (req, res) => { /* Unchanged */ });
app.post('/my-files/delete', isAuthenticated, (req, res) => { /* Unchanged */ });
app.get('/share/:id', (req, res) => { /* Unchanged */ });
app.get('/download/:id', (req, res) => { /* Unchanged */ });
app.post('/files/toggle-embed', isAuthenticated, (req, res) => { /* Unchanged */ });

// --- 6. Authentication Routes ---
app.get('/register', (req, res) => { /* Unchanged */ });
app.post('/register', (req, res) => { /* Unchanged */ });
app.get('/login', (req, res) => { /* Unchanged */ });

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).send("Database error.");
        if (user && await bcrypt.compare(password, user.password)) {
            if (user.status === 'banned') {
                const reason = user.ban_reason || "No reason provided";
                const bodyContent = `<main class="text-center"><div class="glass-panel" style="padding: 40px;"><h1 class="page-title" style="text-align:center; font-size: 3rem;">🚫</h1><h2 class="section-header">Account Banned</h2><p>You have been banned by an administrator.</p><p style="color: var(--text-secondary); margin-top: 20px; border-top: 1px solid var(--glass-border); padding-top: 20px;"><strong>Reason:</strong> ${reason}</p></div></main>`;
                return renderPage(res, bodyContent, { title: 'Account Banned' });
            }
            const userIp = req.ip;
            const fingerprint = generateFingerprint(req);
            db.run('UPDATE users SET last_login_ip = ?, last_fingerprint = ? WHERE username = ?', [userIp, fingerprint, username]);
            req.session.user = { username: user.username, role: user.role };
            res.redirect('/my-files');
        } else {
            req.session.flash = { type: 'error', message: 'Invalid username or password.', field: 'all', inputValue: username };
            res.redirect('/login');
        }
    });
});

app.get('/logout', (req, res) => { /* Unchanged */ });

// --- 7. Admin Routes ---
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT * FROM users", [], (err, users) => {
        if (err) return res.status(500).send("Database error fetching users.");
        db.all('SELECT * FROM files', [], (err, allFiles) => {
            if (err) return res.status(500).send("Database error fetching files.");
            const userListHtml = users.length > 0 ? '<ul>' + users.map(user => {
                const isBanned = user.status === 'banned';
                let actionsHtml = '';
                if (user.username !== req.session.user.username) {
                    if (isBanned) {
                        actionsHtml += `<form action="/admin/users/status" method="post" style="margin:0; background:none;"><input type="hidden" name="username" value="${user.username}"><input type="hidden" name="action" value="unban"><button type="submit" class="btn btn-success">Unban</button></form>`;
                    } else {
                        actionsHtml += `<button type="button" class="btn btn-danger open-ban-modal" data-username="${user.username}">Ban</button>`;
                    }
                    if (user.role !== 'admin') {
                        actionsHtml += `<form ...>...</form>`; // Promote
                    }
                    actionsHtml += `<form ...>...</form>`; // Delete
                } else {
                    actionsHtml = '<span>(This is you)</span>';
                }
                return `<li class="file-item glass-panel">...<div class="file-actions">${actionsHtml}</div></li>`;
            }).join('') + '</ul>' : '<p>No users to manage.</p>';
            const fileListHtml = `...`;
            const bodyContent = `<main>...${userListHtml}...${fileListHtml}</main>`;
            renderPage(res, bodyContent);
        });
    });
});

app.post('/admin/users/status', isAuthenticated, isAdmin, (req, res) => {
    const { username, action, reason } = req.body;
    const newStatus = action === 'ban' ? 'banned' : 'active';
    const banReason = action === 'ban' ? (reason || "No reason provided.") : null;
    if (username === req.session.user.username) { return res.redirect('/admin'); }
    if (action === 'ban') {
        db.get('SELECT last_login_ip, last_fingerprint FROM users WHERE username = ?', [username], (err, user) => {
            if (user && user.last_login_ip) { db.run('INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)', [user.last_login_ip]); }
            if (user && user.last_fingerprint) { db.run('INSERT OR IGNORE INTO banned_fingerprints (fingerprint) VALUES (?)', [user.last_fingerprint]); }
        });
    }
    db.run("UPDATE users SET status = ?, ban_reason = ? WHERE username = ?", [newStatus, banReason, username], (err) => {
        if (err) return res.status(500).send("Database error updating user status.");
        res.redirect('/admin');
    });
});
app.post('/admin/files/delete', isAuthenticated, isAdmin, (req, res) => { /* Unchanged */ });
app.post('/admin/users/promote', isAuthenticated, isAdmin, (req, res) => { /* Unchanged */ });
app.post('/admin/users/delete', isAuthenticated, isAdmin, (req, res) => { /* Unchanged */ });

// --- 8. Start Server ---
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});