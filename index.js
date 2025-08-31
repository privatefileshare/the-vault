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
    // UPDATED TABLES to store ban reasons
    db.run(`CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY NOT NULL, banned_user TEXT, reason TEXT, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    db.run(`CREATE TABLE IF NOT EXISTS banned_fingerprints (fingerprint TEXT PRIMARY KEY NOT NULL, banned_user TEXT, reason TEXT, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
});

// --- 2. Security & Core Middleware ---
app.set('trust proxy', 1);

app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('hex');
    next();
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
        },
    },
}));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

function generateFingerprint(req) {
    const userAgent = req.headers['user-agent'] || '';
    const acceptLanguage = req.headers['accept-language'] || '';
    const fingerprintString = `${userAgent}${acceptLanguage}`;
    return crypto.createHash('sha256').update(fingerprintString).digest('hex');
}

// --- UPDATED MIDDLEWARE to show ban reason on Access Denied page ---
app.use((req, res, next) => {
    const userIp = req.ip;
    const fingerprint = generateFingerprint(req);
    db.get('SELECT * FROM banned_ips WHERE ip = ?', [userIp], (err, ipRow) => {
        if (err) return next();
        if (ipRow) {
            const reason = ipRow.reason || "No reason provided";
            const bodyContent = `<main class="centered-container"><div class="glass-panel text-center"><h1 class="page-title">🚫 Access Denied</h1><p style="font-size: 1.1rem;">This IP address has been banned by an Admin!<br><strong>Reason:</strong> ${reason}</p></div></main>`;
            return renderPage(res, bodyContent, { title: 'Access Denied', hideNav: true });
        }
        db.get('SELECT * FROM banned_fingerprints WHERE fingerprint = ?', [fingerprint], (err, fpRow) => {
            if (err) return next();
            if (fpRow) {
                const reason = fpRow.reason || "No reason provided";
                const bodyContent = `<main class="centered-container"><div class="glass-panel text-center"><h1 class="page-title">🚫 Access Denied</h1><p style="font-size: 1.1rem;">This device has been banned by an Admin!<br><strong>Reason:</strong> ${reason}</p></div></main>`;
                return renderPage(res, bodyContent, { title: 'Access Denied', hideNav: true });
            }
            next();
        });
    });
});

app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true, cookie: { secure: process.env.NODE_ENV === 'production', httpOnly: true, sameSite: 'strict' } }));
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
    const navBar = options.hideNav ? '' : `
        <nav class="navbar glass-panel">
            <a href="/" class="nav-brand">The Vault</a>
            <div class="nav-links">
                ${res.locals.user.role === 'admin' ? '<a href="/admin" class="nav-link">Admin Panel</a>' : ''}
                <a href="/my-files" class="nav-link">My Files</a>
                <a href="/settings" class="nav-link">Settings</a>
                <a href="/logout" class="nav-link">Logout</a>
            </div>
        </nav>`;

    res.send(`
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${options.title || 'The Vault'}</title>
        ${options.metaTags || ''}
        <link rel="icon" type="image/png" href="/favicon.png">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary-purple: #a855f7; --glow-purple: rgba(168, 85, 247, 0.5);
                --text-primary: #e5e7eb; --text-secondary: #9ca3af;
                --glass-bg: rgba(31, 29, 46, 0.5); --glass-border: rgba(255, 255, 255, 0.1);
                --danger-color: #f43f5e; --danger-glow: rgba(244, 63, 94, 0.5);
                --success-color: #22c55e; --success-glow: rgba(34, 197, 94, 0.5);
            }
            *, *::before, *::after { box-sizing: border-box; }
            @keyframes rotate { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            body { font-family: 'Inter', sans-serif; margin: 0; background-color: #111827; color: var(--text-primary); overflow-x: hidden; position: relative; min-height: 100vh; }
            body::before { content: ''; position: fixed; width: 600px; height: 600px; filter: blur(150px); background-image: linear-gradient(45deg, #7c3aed, #db2777); top: -150px; left: -150px; animation: rotate 20s cubic-bezier(0.8, 0.2, 0.2, 0.8) alternate infinite; border-radius: 9999px; z-index: -1; }
            .container { max-width: 900px; margin: 0 auto; padding: 20px; z-index: 1; position: relative; }
            .centered-container { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
            .glass-panel { background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 16px; backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37); padding: 30px; }
            .page-title { font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #ec4899, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0 0 30px 0; }
            .section-header { font-size: 1.5rem; font-weight: 600; margin: 0 0 20px 0; color: var(--primary-purple); border-bottom: 1px solid var(--glass-border); padding-bottom: 10px; }
            .btn { text-decoration: none; display: inline-flex; align-items: center; justify-content: center; color: white; font-weight: 500; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; transition: all 0.2s ease; white-space: nowrap; font-size: 1rem; }
            .btn-primary { background-color: var(--primary-purple); } .btn-primary:hover { background-color: #9333ea; box-shadow: 0 0 20px var(--glow-purple); transform: translateY(-2px); }
            .btn-secondary { background-color: rgba(255, 255, 255, 0.1); border: 1px solid var(--glass-border); } .btn-secondary:hover { background-color: rgba(255, 255, 255, 0.2); }
            .btn-danger { background-color: var(--danger-color); } .btn-danger:hover { background-color: #be123c; box-shadow: 0 0 20px var(--danger-glow); }
            .btn-success { background-color: var(--success-color); } .btn-success:hover { background-color: #16a34a; box-shadow: 0 0 20px var(--success-glow); }
            .navbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; padding: 15px 30px; }
            .nav-brand { font-size: 1.5rem; font-weight: bold; color: var(--text-primary); text-decoration: none; }
            .nav-links { display: flex; gap: 20px; }
            .nav-link { color: var(--text-secondary); text-decoration: none; font-weight: 500; transition: color 0.2s; } .nav-link:hover { color: var(--primary-purple); }
            form { display: flex; flex-direction: column; gap: 20px; margin: 0; padding: 0; }
            .text-center { text-align: center; }
            input[type="text"], input[type="password"] { background-color: rgba(0,0,0,0.2); color: var(--text-primary); border: 1px solid var(--glass-border); padding: 12px; border-radius: 8px; font-size: 1em; transition: all 0.2s ease; }
            input:focus { border-color: var(--primary-purple); box-shadow: 0 0 10px 1px var(--glow-purple); outline: none; }
            .flash-message { padding: 15px; margin-bottom: 20px; border-radius: 8px; font-weight: 500; }
            .flash-success { background-color: rgba(34, 197, 94, 0.2); border: 1px solid var(--success-color); color: var(--success-color); }
            .flash-error { background-color: rgba(244, 63, 94, 0.2); border: 1px solid var(--danger-color); color: var(--danger-color); }
            .error-message { color: var(--danger-color); font-size: 0.9rem; text-align: left; }
            .fine-print { margin-top: 20px; color: var(--text-secondary); font-size: 0.9rem; }
            .fine-print a { color: var(--primary-purple); text-decoration: none; } .fine-print a:hover { text-decoration: underline; }
            .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); display: none; align-items: center; justify-content: center; z-index: 1000; }
            .modal-content { padding: 30px; width: 90%; max-width: 500px; }
            .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
            .file-list { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 15px; }
            .file-item { display: flex; align-items: center; gap: 15px; padding: 20px; }
            .file-details { flex-grow: 1; overflow: hidden; }
            .file-name { font-size: 1.1rem; font-weight: 500; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .file-meta { font-size: 0.9rem; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .file-actions { display: flex; gap: 10px; flex-shrink: 0; }
            .file-input-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border-width: 0; }
            .upload-actions { display: flex; align-items: center; gap: 15px; }
            #file-name-display { color: var(--text-secondary); flex-grow: 1; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; background-color: rgba(0,0,0,0.2); border: 1px solid var(--glass-border); border-radius: 8px; padding: 12px; }
            .share-card { display: flex; align-items: center; justify-content: space-between; gap: 20px; }
            #copy-confirm { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background-color: var(--success-color); color: white; padding: 10px 20px; border-radius: 8px; z-index: 2000; opacity: 0; transition: opacity 0.3s ease; pointer-events: none; }
            #copy-confirm.show { opacity: 1; }
        </style>
        </head><body>
            ${navBar}
            <div class="container">
                ${bodyContent}
            </div>
            <div id="copy-confirm"></div>
            <div id="ban-modal" class="modal-overlay">
                <div class="modal-content glass-panel">
                    <h3>Confirm User Ban</h3>
                    <form id="ban-reason-form" method="post" action="/admin/users/status">
                        <input type="text" id="ban-reason-input" name="reason" placeholder="Enter reason for the ban..." required>
                        <input type="hidden" id="ban-username-input" name="username">
                        <input type="hidden" name="action" value="ban">
                        <div class="modal-actions">
                            <button type="button" id="cancel-ban-btn" class="btn btn-secondary">Cancel</button>
                            <button type="submit" class="btn btn-danger">Confirm Ban</button>
                        </div>
                    </form>
                </div>
            </div>
            <script nonce="${res.locals.nonce}">
                document.addEventListener('DOMContentLoaded', () => {
                    document.body.addEventListener('click', event => {
                        if (event.target.classList.contains('open-ban-modal')) {
                            event.preventDefault();
                            document.getElementById('ban-username-input').value = event.target.dataset.username;
                            document.getElementById('ban-modal').style.display = 'flex';
                        }
                    });
                    const banModal = document.getElementById('ban-modal');
                    if(banModal) {
                        document.getElementById('cancel-ban-btn').addEventListener('click', () => banModal.style.display = 'none');
                        banModal.addEventListener('click', (e) => { if (e.target === banModal) banModal.style.display = 'none'; });
                    }
                    const fileInput = document.getElementById('file-input');
                    if (fileInput) {
                        fileInput.addEventListener('change', function() {
                            document.getElementById('file-name-display').textContent = this.files.length > 0 ? this.files[0].name : 'No file selected';
                        });
                    }
                    function showCopyConfirmation() {
                        const confirmPopup = document.getElementById('copy-confirm');
                        confirmPopup.textContent = 'Link copied to clipboard!';
                        confirmPopup.classList.add('show');
                        setTimeout(() => { confirmPopup.classList.remove('show'); }, 2000);
                    }
                    document.querySelectorAll('.copy-link-btn').forEach(button => {
                        button.addEventListener('click', () => {
                            navigator.clipboard.writeText(button.dataset.link).then(showCopyConfirmation);
                        });
                    });
                });
            </script>
        </body></html>`);
}

// --- 5. Main Routes ---
app.get('/', (req, res) => {
    if (req.session.user) return res.redirect('/my-files');
    const bodyContent = `
        <main class="centered-container">
            <div class="glass-panel text-center" style="max-width: 500px;">
                <h1 class="page-title">Welcome to The Vault</h1>
                <p style="color: var(--text-secondary); font-size: 1.1rem; margin-bottom: 30px;">Your secure and stylish corner of the cloud.</p>
                <a href="/register" class="btn btn-primary" style="width: 100%;">Create Your Account</a>
                <p class="fine-print">Have an account already? <a href="/login">Login here</a></p>
            </div>
        </main>`;
    renderPage(res, bodyContent, { title: 'Welcome to The Vault', hideNav: true });
});

app.get('/my-files', isAuthenticated, (req, res) => {
    db.all('SELECT * FROM files WHERE owner = ? ORDER BY originalName ASC', [req.session.user.username], (err, userFiles) => {
        if (err) { console.error(err); return res.status(500).send("Database error."); }
        const fileListHtml = userFiles.length > 0 ? `<ul class="file-list">${userFiles.map(file => `
            <li class="file-item glass-panel">
                <div class="file-details">
                    <a href="/share/${file.id}" class="file-name" title="${file.originalName}">${file.originalName}</a>
                    <div class="file-meta">Size: ${formatBytes(file.size)}</div>
                </div>
                <div class="file-actions">
                    <button type="button" class="btn btn-secondary copy-link-btn" data-link="${DOMAIN}/share/${file.id}">Copy Link</button>
                    <a href="/download/${file.id}" class="btn btn-primary">Download</a>
                    <form action="/my-files/delete" method="post"><input type="hidden" name="id" value="${file.id}"><button type="submit" class="btn btn-danger">Delete</button></form>
                </div>
            </li>`).join('')}</ul>`
            : '<div class="glass-panel text-center"><p>Your vault is empty. Upload a file below!</p></div>';
        const uploadForm = `
            <div class="glass-panel" style="margin-top: 40px;">
                <form id="upload-form" action="/upload" method="post" enctype="multipart/form-data">
                    <h2 class="section-header">Upload New File</h2>
                    <div class="upload-actions">
                        <label for="file-input" class="btn btn-secondary">Browse Files...</label>
                        <span id="file-name-display">No file selected</span>
                        <button type="submit" class="btn btn-primary">Upload File</button>
                    </div>
                    <input type="file" name="sharedFile" id="file-input" class="file-input-hidden" required>
                </form>
            </div>`;
        renderPage(res, `<main><h1 class="page-title">My Vault</h1>${fileListHtml}${uploadForm}</main>`, { title: 'My Vault' });
    });
});

app.post('/upload', isAuthenticated, upload.single('sharedFile'), (req, res) => {
    if (!req.file) return res.status(400).send("No file uploaded.");
    const id = crypto.randomBytes(4).toString('hex');
    const { originalname, filename, size } = req.file;
    db.run('INSERT INTO files (id, owner, originalName, storedName, size) VALUES (?, ?, ?, ?, ?)', [id, req.session.user.username, originalname, filename, size], (err) => {
        if (err) { console.error(err); return res.status(500).send("Error saving file info."); }
        res.redirect('/my-files');
    });
});

app.post('/my-files/delete', isAuthenticated, (req, res) => {
    const { id } = req.body;
    db.get('SELECT storedName FROM files WHERE id = ? AND owner = ?', [id, req.session.user.username], (err, row) => {
        if (err || !row) return res.status(404).send('File not found or permission denied.');
        fs.unlink(path.join(UPLOAD_DIR, row.storedName), (unlinkErr) => {
            if (unlinkErr) console.error("File deletion error:", unlinkErr);
            db.run('DELETE FROM files WHERE id = ?', [id], () => res.redirect('/my-files'));
        });
    });
});

app.get('/share/:id', (req, res) => {
    const { id } = req.params;
    db.get('SELECT * FROM files WHERE id = ?', [id], (err, file) => {
        if (err || !file) {
            const bodyContent = `<main class="centered-container"><div class="glass-panel text-center"><h1 class="page-title">404</h1><h2>File Not Found</h2><p>This file may have been moved or deleted.</p></div></main>`;
            return renderPage(res, bodyContent, { title: 'Not Found', hideNav: true });
        }
        const fileUrl = `${DOMAIN}/download/${file.id}`;
        const secureFileUrl = fileUrl.replace('http://', 'https://');
        let metaTags = `
            <meta property="og:title" content="${file.originalName}">
            <meta property="og:description" content="Download ${file.originalName} (${formatBytes(file.size)}), shared via The Vault.">
            <meta property="og:site_name" content="The Vault">
            <meta property="og:url" content="${DOMAIN}/share/${file.id}">
            <meta name="theme-color" content="#a855f7">
        `;
        const mimeType = mime.lookup(file.originalName);
        if (mimeType && mimeType.startsWith('image/')) {
            metaTags += `<meta property="og:image" content="${secureFileUrl}"><meta name="twitter:card" content="summary_large_image">`;
        } else if (mimeType && mimeType.startsWith('video/')) {
            metaTags += `<meta property="og:type" content="video.other"><meta property="og:video" content="${secureFileUrl}"><meta property="og:video:secure_url" content="${secureFileUrl}"><meta property="og:video:type" content="${mimeType}"><meta property="og:video:width" content="1280"><meta property="og:video:height" content="720"><meta name="twitter:card" content="player"><meta name="twitter:player" content="${secureFileUrl}">`;
        } else {
            metaTags += `<meta name="twitter:card" content="summary">`;
        }
        let embedContent = `<div class="share-card"><div class="share-details"><p class="share-filename" title="${file.originalName}">${file.originalName}</p><p class="share-meta">Owner: ${file.owner} &bull; Size: ${formatBytes(file.size)}</p></div><a href="${fileUrl}" class="btn btn-primary">Download</a></div>`;
        const body = `<main class="centered-container"><div class="glass-panel" style="width:100%; max-width:600px;"><h2 class="section-header">Shared File</h2>${embedContent}</div></main>`;
        renderPage(res, body, { title: `Share - ${file.originalName}`, hideNav: true, metaTags: metaTags });
    });
});

app.get('/download/:id', (req, res) => {
    const { id } = req.params;
    db.get('SELECT storedName, originalName FROM files WHERE id = ?', [id], (err, row) => {
        if (err || !row) return res.status(404).send('File not found.');
        res.download(path.join(UPLOAD_DIR, row.storedName), row.originalName);
    });
});

// --- 6. Authentication & Settings Routes ---
app.get('/register', (req, res) => {
    if (req.session.user) return res.redirect('/my-files');
    const bodyContent = `
        <main class="centered-container">
            <div class="glass-panel" style="max-width: 450px; width: 100%;">
                <form action="/register" method="post">
                    <h1 class="page-title text-center">Create Account</h1>
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <input type="password" name="confirmPassword" placeholder="Confirm Password" required>
                    <button type="submit" class="btn btn-primary">Register</button>
                    <p class="fine-print text-center">Have an account already? <a href="/login">Login here</a></p>
                </form>
            </div>
        </main>`;
    renderPage(res, bodyContent, { title: 'Register', hideNav: true });
});

app.post('/register', (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (password !== confirmPassword) {
        req.session.flash = { type: 'error', message: 'Passwords do not match.' };
        return res.redirect('/register');
    }
    db.get('SELECT username FROM users WHERE username = ?', [username], async (err, row) => {
        if (row) {
            req.session.flash = { type: 'error', message: 'Username is already taken.' };
            return res.redirect('/register');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        db.get('SELECT COUNT(*) as count FROM users', (err, countRow) => {
            const role = countRow.count === 0 ? 'admin' : 'user';
            db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], (err) => {
                if (err) return res.status(500).send("Database error during registration.");
                res.redirect('/login');
            });
        });
    });
});

app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/my-files');
    const { message = '' } = res.locals.flash || {};
    const bodyContent = `
        <main class="centered-container">
            <div class="glass-panel" style="max-width: 450px; width: 100%;">
                <form action="/login" method="post">
                    <h1 class="page-title text-center">Welcome Back</h1>
                     ${message ? `<p class="error-message text-center">${message}</p>` : ''}
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit" class="btn btn-primary">Login</button>
                    <p class="fine-print text-center">Don't have an account? <a href="/register">Register here</a></p>
                </form>
            </div>
        </main>`;
    renderPage(res, bodyContent, { title: 'Login', hideNav: true });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).send("Database error.");
        if (user && await bcrypt.compare(password, user.password)) {
            if (user.status === 'banned') {
                const reason = user.ban_reason || "No reason provided";
                const bodyContent = `<main class="centered-container"><div class="glass-panel text-center"><h1 class="page-title">🚫 Account Banned</h1><p style="font-size: 1.1rem;">You have been banned by an Admin!<br><strong>Reason:</strong> ${reason}</p></div></main>`;
                return renderPage(res, bodyContent, { title: 'Account Banned', hideNav: true });
            }
            const userIp = req.ip;
            const fingerprint = generateFingerprint(req);
            db.run('UPDATE users SET last_login_ip = ?, last_fingerprint = ? WHERE username = ?', [userIp, fingerprint, username]);
            req.session.user = { username: user.username, role: user.role };
            res.redirect('/my-files');
        } else {
            req.session.flash = { message: 'Invalid username or password.' };
            res.redirect('/login');
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

app.get('/settings', isAuthenticated, (req, res) => {
    const flash = res.locals.flash || {};
    const bodyContent = `
        <h1 class="page-title">Account Settings</h1>
        ${flash.message ? `<div class="flash-message ${flash.type === 'success' ? 'flash-success' : 'flash-error'}">${flash.message}</div>` : ''}
        <div class="glass-panel" style="margin-bottom: 30px;">
            <h2 class="section-header">Change Username</h2>
            <form action="/settings/username" method="post">
                <input type="text" name="newUsername" placeholder="Enter new username" required>
                <button type="submit" class="btn btn-primary">Update Username</button>
            </form>
        </div>
        <div class="glass-panel">
            <h2 class="section-header">Change Password</h2>
            <form action="/settings/password" method="post">
                <input type="password" name="currentPassword" placeholder="Current password" required>
                <input type="password" name="newPassword" placeholder="New password" required>
                <input type="password" name="confirmPassword" placeholder="Confirm new password" required>
                <button type="submit" class="btn btn-primary">Update Password</button>
            </form>
        </div>
    `;
    renderPage(res, bodyContent, { title: 'Settings' });
});

app.post('/settings/username', isAuthenticated, (req, res) => {
    const { newUsername } = req.body;
    const currentUsername = req.session.user.username;

    db.get('SELECT username FROM users WHERE username = ?', [newUsername], (err, row) => {
        if (row) {
            req.session.flash = { type: 'error', message: 'Username is already taken.' };
            return res.redirect('/settings');
        }
        
        db.serialize(() => {
            db.run('UPDATE users SET username = ? WHERE username = ?', [newUsername, currentUsername]);
            db.run('UPDATE files SET owner = ? WHERE owner = ?', [newUsername, currentUsername], (err) => {
                if (err) {
                     req.session.flash = { type: 'error', message: 'Failed to update file ownerships.' };
                     return res.redirect('/settings');
                }
                req.session.user.username = newUsername; // Update session
                req.session.flash = { type: 'success', message: 'Username successfully updated!' };
                res.redirect('/settings');
            });
        });
    });
});

app.post('/settings/password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const username = req.session.user.username;

    if (newPassword !== confirmPassword) {
        req.session.flash = { type: 'error', message: 'New passwords do not match.' };
        return res.redirect('/settings');
    }

    db.get('SELECT password FROM users WHERE username = ?', [username], async (err, user) => {
        if (!user || !await bcrypt.compare(currentPassword, user.password)) {
            req.session.flash = { type: 'error', message: 'Incorrect current password.' };
            return res.redirect('/settings');
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 10);
        db.run('UPDATE users SET password = ? WHERE username = ?', [hashedNewPassword, username], (err) => {
            if (err) {
                req.session.flash = { type: 'error', message: 'Error updating password.' };
            } else {
                req.session.flash = { type: 'success', message: 'Password successfully updated!' };
            }
            res.redirect('/settings');
        });
    });
});

// --- 7. Admin Routes ---
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT * FROM users", [], (err, users) => {
        if (err) return res.status(500).send("Database error fetching users.");
        db.all('SELECT * FROM files', [], (err, allFiles) => {
            if (err) return res.status(500).send("Database error fetching files.");
            const userListHtml = users.map(user => {
                const isBanned = user.status === 'banned';
                let actionsHtml = '';
                if (user.username !== req.session.user.username) {
                    actionsHtml += isBanned ? `<form action="/admin/users/status" method="post"><input type="hidden" name="username" value="${user.username}"><input type="hidden" name="action" value="unban"><button type="submit" class="btn btn-success">Unban</button></form>`
                                           : `<button type="button" class="btn btn-danger open-ban-modal" data-username="${user.username}">Ban</button>`;
                    if (user.role !== 'admin') actionsHtml += `<form action="/admin/users/promote" method="post"><input type="hidden" name="username" value="${user.username}"><button type="submit" class="btn btn-secondary">Promote</button></form>`;
                    actionsHtml += `<form action="/admin/users/delete" method="post"><input type="hidden" name="username" value="${user.username}"><button type="submit" class="btn btn-danger">Delete</button></form>`;
                } else {
                    actionsHtml = '<span style="color:var(--text-secondary)">(This is you)</span>';
                }
                return `<li class="file-item glass-panel">
                            <div class="file-details">
                                <span class="file-name">${user.username} <span style="font-weight:400; font-size:0.9rem; color:var(--${isBanned ? 'danger' : 'success'}-color);">- ${isBanned ? 'Banned' : 'Active'}</span></span>
                                <div class="file-meta">Role: ${user.role} &bull; IP: ${user.last_login_ip || 'N/A'}</div>
                            </div><div class="file-actions">${actionsHtml}</div></li>`;
            }).join('');
            const fileListHtml = allFiles.map(file => `
                <li class="file-item glass-panel">
                    <div class="file-details">
                        <a href="/share/${file.id}" class="file-name" title="${file.originalName}">${file.originalName}</a>
                        <div class="file-meta">Owner: ${file.owner} &bull; Size: ${formatBytes(file.size)}</div>
                    </div><div class="file-actions"><form action="/admin/files/delete" method="post"><input type="hidden" name="id" value="${file.id}"><button type="submit" class="btn btn-danger">Delete</button></form></div></li>`
            ).join('');
            const bodyContent = `<main><h1 class="page-title">Admin Panel</h1>
                <div class="glass-panel" style="margin-bottom: 30px;"><h2 class="section-header">Manage Users</h2><ul class="file-list">${userListHtml}</ul></div>
                <div class="glass-panel"><h2 class="section-header">Manage All Files</h2><ul class="file-list">${fileListHtml}</ul></div></main>`;
            renderPage(res, bodyContent, { title: 'Admin Panel' });
        });
    });
});

// --- UPDATED ROUTE to manage IP/fingerprint bans along with user status ---
app.post('/admin/users/status', isAuthenticated, isAdmin, (req, res) => {
    const { username, action, reason } = req.body;
    const newStatus = action === 'ban' ? 'banned' : 'active';
    const banReason = action === 'ban' ? (reason || "No reason provided.") : null;

    if (username === req.session.user.username) return res.redirect('/admin');

    db.get('SELECT last_login_ip, last_fingerprint FROM users WHERE username = ?', [username], (err, user) => {
        if (err) { console.error(err); return res.redirect('/admin'); }

        if (action === 'ban') {
            if (user && user.last_login_ip) {
                db.run('INSERT OR REPLACE INTO banned_ips (ip, banned_user, reason) VALUES (?, ?, ?)', [user.last_login_ip, username, banReason]);
            }
            if (user && user.last_fingerprint) {
                db.run('INSERT OR REPLACE INTO banned_fingerprints (fingerprint, banned_user, reason) VALUES (?, ?, ?)', [user.last_fingerprint, username, banReason]);
            }
        } else { // action === 'unban'
            if (user && user.last_login_ip) {
                db.run('DELETE FROM banned_ips WHERE ip = ?', [user.last_login_ip]);
            }
            if (user && user.last_fingerprint) {
                db.run('DELETE FROM banned_fingerprints WHERE fingerprint = ?', [user.last_fingerprint]);
            }
        }
    });

    db.run("UPDATE users SET status = ?, ban_reason = ? WHERE username = ?", [newStatus, banReason, username], () => res.redirect('/admin'));
});

app.post('/admin/files/delete', isAuthenticated, isAdmin, (req, res) => {
    db.get('SELECT storedName FROM files WHERE id = ?', [req.body.id], (err, row) => {
        if (err || !row) return res.status(404).send('File not found.');
        fs.unlink(path.join(UPLOAD_DIR, row.storedName), () => db.run('DELETE FROM files WHERE id = ?', [req.body.id], () => res.redirect('/admin')));
    });
});

app.post('/admin/users/promote', isAuthenticated, isAdmin, (req, res) => {
    db.run("UPDATE users SET role = 'admin' WHERE username = ?", [req.body.username], () => res.redirect('/admin'));
});

app.post('/admin/users/delete', isAuthenticated, isAdmin, (req, res) => {
    const { username } = req.body;
    if (username === req.session.user.username) return res.redirect('/admin');
    db.all('SELECT storedName FROM files WHERE owner = ?', [username], (err, files) => {
        files.forEach(file => fs.unlink(path.join(UPLOAD_DIR, file.storedName), () => {}));
        db.run('DELETE FROM files WHERE owner = ?', [username], () => db.run('DELETE FROM users WHERE username = ?', [username], () => res.redirect('/admin')));
    });
});

// --- 8. Start Server ---
app.listen(PORT, () => console.log(`🚀 Server is running on port ${PORT}`));