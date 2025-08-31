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

app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('hex');
    next();
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://cdn.jsdelivr.net"],
            "style-src-elem": ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://fonts.googleapis.com"],
            "style-src-attr": ["'unsafe-inline'"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
        },
    },
}));

app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use((req, res, next) => {
    const userIp = req.ip;
    db.get('SELECT fingerprint FROM banned_fingerprints WHERE fingerprint = ?', [req.body.fingerprint], (err, fpRow) => {
         if (fpRow) {
            const bodyContent = `<main class="centered-container"><div class="glass-panel text-center"><h1>Access Denied</h1><p>Your device has been banned.</p></div></main>`;
            return renderPage(res, bodyContent, { title: 'Access Denied', hideNav: true });
        }
        db.get('SELECT ip FROM banned_ips WHERE ip = ?', [userIp], (err, ipRow) => {
            if (ipRow) {
                const bodyContent = `<main class="centered-container"><div class="glass-panel text-center"><h1>Access Denied</h1><p>Your IP address has been banned.</p></div></main>`;
                return renderPage(res, bodyContent, { title: 'Access Denied', hideNav: true });
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
    const navBar = options.hideNav ? '' : `
        <nav class="navbar glass-panel">
            <a href="/" class="nav-brand">The Vault</a>
            <div class="nav-links">
                <a href="/my-files" class="nav-link">My Files</a>
                <a href="/settings" class="nav-link">Settings</a>
                ${res.locals.user.role === 'admin' ? '<a href="/admin" class="nav-link">Admin Panel</a>' : ''}
                <a href="/logout" class="nav-link">Logout</a>
            </div>
        </nav>`;

    res.send(`
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${options.title || 'The Vault'}</title>
        ${options.metaTags || ''}
        <link rel="icon" type="image/png" href="/favicon.png">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style nonce="${res.locals.nonce}">
            :root {
                --primary-purple: #a855f7; --glow-purple: rgba(168, 85, 247, 0.5);
                --text-primary: #e5e7eb; --text-secondary: #9ca3af;
                --glass-bg: rgba(31, 29, 46, 0.5); --glass-border: rgba(255, 255, 255, 0.1);
                --danger-color: #f43f5e; --danger-glow: rgba(244, 63, 94, 0.5);
                --success-color: #22c55e; --success-glow: rgba(34, 197, 94, 0.5);
            }
            *, *::before, *::after { box-sizing: border-box; }
            body { font-family: 'Inter', sans-serif; margin: 0; background-color: #111827; color: var(--text-primary); overflow-x: hidden; position: relative; min-height: 100vh; }
            body::before { content: ''; position: fixed; width: 600px; height: 600px; filter: blur(150px); background: linear-gradient(45deg, #7c3aed, #db2777); top: -150px; left: -150px; animation: rotate 20s cubic-bezier(.8,.2,.2,.8) alternate infinite; border-radius: 9999px; z-index: -1; }
            .container { max-width: 900px; margin: 0 auto; padding: 20px; z-index: 1; position: relative; }
            .centered-container { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
            .glass-panel { background: var(--glass-bg); border: 1px solid var(--glass-border); border-radius: 16px; backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37); padding: 30px; }
            .page-title { font-size: 2.5rem; font-weight: 700; background: linear-gradient(90deg, #ec4899, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0 0 30px 0; }
            .section-header { font-size: 1.5rem; font-weight: 600; margin: 0 0 20px 0; color: var(--primary-purple); border-bottom: 1px solid var(--glass-border); padding-bottom: 10px; }
            .btn { text-decoration: none; display: inline-flex; align-items: center; justify-content: center; color: white; font-weight: 500; padding: 12px 24px; border: none; border-radius: 8px; cursor: pointer; transition: all 0.2s ease; white-space: nowrap; font-size: 1rem; }
            .navbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; padding: 15px 30px; }
            form { display: flex; flex-direction: column; gap: 20px; margin: 0; padding: 0; }
            input[type="text"], input[type="password"] { background-color: rgba(0,0,0,0.2); color: var(--text-primary); border: 1px solid var(--glass-border); padding: 12px; border-radius: 8px; font-size: 1em; }
            .file-list { list-style: none; padding: 0; display: flex; flex-direction: column; gap: 15px; }
            .file-item { display: flex; align-items: center; gap: 15px; padding: 20px; }
            .file-details { flex-grow: 1; overflow: hidden; }
            .file-name { font-size: 1.1rem; font-weight: 500; color: var(--text-primary); }
            .file-actions { display: flex; gap: 10px; flex-shrink: 0; }
            .file-input-hidden { display: none; }
            .progress-bar-container { width: 100%; background-color: rgba(0,0,0,0.2); border-radius: 8px; overflow: hidden; height: 10px; display: none; }
            .progress-bar { width: 0%; height: 100%; background-color: var(--primary-purple); transition: width 0.2s ease-out; }
            #copy-confirm { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); background-color: var(--success-color); color: white; padding: 10px 20px; border-radius: 8px; z-index: 2000; opacity: 0; transition: opacity 0.3s ease; pointer-events: none; }
            #copy-confirm.show { opacity: 1; }
            .flash-message { padding: 15px; margin-bottom: 20px; border-radius: 8px; text-align: center; }
            .flash-success { background-color: rgba(34, 197, 94, 0.2); border: 1px solid var(--success-color); }
            .flash-error { background-color: rgba(244, 63, 94, 0.2); border: 1px solid var(--danger-color); }
            .text-center { text-align: center; }
            .upload-actions { display: flex; align-items: center; gap: 15px; }
            #file-name-display { color: var(--text-secondary); flex-grow: 1; text-align: left; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; background-color: rgba(0,0,0,0.2); border: 1px solid var(--glass-border); border-radius: 8px; padding: 12px; }
            .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); display: none; align-items: center; justify-content: center; z-index: 1000; }
            .modal-content { padding: 30px; width: 90%; max-width: 500px; }

            @media (max-width: 768px) {
                body { padding: 20px 10px; }
                .glass-panel { padding: 20px; }
                .page-title { font-size: 2rem; }
                .navbar { flex-direction: column; gap: 15px; }
                .nav-links { flex-wrap: wrap; justify-content: center; }
                .file-item { flex-direction: column; align-items: flex-start; gap: 20px; }
                .file-actions { width: 100%; justify-content: flex-end; flex-wrap: wrap; }
                .upload-actions { flex-direction: column; align-items: stretch; }
            }
        </style>
        </head><body>
            ${navBar || (options.hideNav ? '' : '<div style="height: 85px;"></div>')}
            <div class="container">
                ${bodyContent}
            </div>
            <div id="copy-confirm"></div>
            <div id="ban-modal" class="modal-overlay">
                 <div class="modal-content glass-panel">
                    <h3>Provide Ban Reason</h3>
                    <form id="ban-reason-form" method="post" action="/admin/users/status" style="background:none; padding:0; gap: 10px;">
                        <input type="text" id="ban-reason-input" name="reason" placeholder="Reason for ban" required>
                        <input type="hidden" id="ban-username-input" name="username">
                        <input type="hidden" name="action" value="ban">
                        <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
                            <button type="button" id="cancel-ban-btn" class="btn btn-secondary">Cancel</button>
                            <button type="submit" class="btn btn-danger">Confirm Ban</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <script src="https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js" nonce="${res.locals.nonce}"></script>
            <script nonce="${res.locals.nonce}">
                function getFingerprint() {
                    return FingerprintJS.load()
                        .then(fp => fp.get())
                        .then(result => result.visitorId);
                }
                
                document.addEventListener('DOMContentLoaded', () => {
                    document.querySelectorAll('.fingerprint-form').forEach(form => {
                        getFingerprint().then(fingerprint => {
                            const input = document.createElement('input');
                            input.type = 'hidden';
                            input.name = 'fingerprint';
                            input.value = fingerprint;
                            form.appendChild(input);
                        });
                    });
                    
                    document.body.addEventListener('click', event => {
                        if (event.target.classList.contains('open-ban-modal')) {
                            const banModal = document.getElementById('ban-modal');
                            if (banModal) {
                                banModal.querySelector('#ban-username-input').value = event.target.dataset.username;
                                banModal.style.display = 'flex';
                            }
                        }
                    });

                    const banModal = document.getElementById('ban-modal');
                    if (banModal) {
                        banModal.querySelector('#cancel-ban-btn').addEventListener('click', () => { banModal.style.display = 'none'; });
                        banModal.addEventListener('click', (e) => { if (e.target === banModal) { banModal.style.display = 'none'; } });
                    }

                    const fileInput = document.getElementById('file-input');
                    if (fileInput) {
                        const fileNameDisplay = document.getElementById('file-name-display');
                        if (fileNameDisplay) {
                            fileInput.addEventListener('change', function() {
                               fileNameDisplay.textContent = this.files.length > 0 ? this.files[0].name : 'No file selected';
                            });
                        }
                    }

                    const uploadForm = document.getElementById('upload-form');
                    if (uploadForm) {
                        uploadForm.addEventListener('submit', function(e) {
                            e.preventDefault();
                            const formData = new FormData(uploadForm);
                            const progressBarContainer = document.getElementById('progress-bar-container');
                            const progressBar = document.getElementById('progress-bar');
                            const uploadButton = uploadForm.querySelector('button[type="submit"]');

                            progressBarContainer.style.display = 'block';
                            uploadButton.disabled = true;
                            uploadButton.textContent = 'Uploading...';

                            const xhr = new XMLHttpRequest();
                            xhr.open('POST', '/upload', true);
                            
                            xhr.upload.onprogress = function(event) {
                                if (event.lengthComputable) {
                                    const percentComplete = (event.loaded / event.total) * 100;
                                    progressBar.style.width = percentComplete + '%';
                                }
                            };
                            
                            xhr.onload = function() {
                                if (xhr.status === 200) {
                                    window.location.href = '/my-files?upload=success';
                                } else {
                                    alert('Upload failed: ' + xhr.responseText);
                                    progressBarContainer.style.display = 'none';
                                    uploadButton.disabled = false;
                                    uploadButton.textContent = 'Upload File';
                                }
                            };
                            
                            xhr.onerror = function() {
                                alert('An error occurred during the upload.');
                                progressBarContainer.style.display = 'none';
                                uploadButton.disabled = false;
                                uploadButton.textContent = 'Upload File';
                            };
                            
                            xhr.send(formData);
                        });
                    }

                    function showCopyConfirmation() {
                        const confirmPopup = document.getElementById('copy-confirm');
                        confirmPopup.textContent = 'Link copied!';
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
    if (req.session.user) {
        return res.redirect('/my-files');
    }
    
    const metaTags = `
        <meta property="og:title" content="The Vault - Secure File Sharing">
        <meta property="og:description" content="Your personal corner of the cloud, secured and styled.">
        <meta property="og:image" content="${DOMAIN}/favicon.png">
        <meta property="og:url" content="${DOMAIN}">
        <meta name="twitter:card" content="summary">
        <meta name="theme-color" content="#a855f7">
    `;

    const bodyContent = `
        <main class="centered-container">
            <div class="glass-panel text-center" style="max-width: 500px;">
                <h1 class="page-title">Welcome to The Vault</h1>
                <p>Your secure and stylish corner of the cloud.</p>
                <a href="/register" class="btn btn-primary" style="width: 100%; margin-top: 20px;">Create Your Account</a>
                <p class="fine-print" style="margin-top:20px;">Have an account already? <a href="/login">Login here</a></p>
            </div>
        </main>`;
    renderPage(res, bodyContent, { title: 'Welcome to The Vault', hideNav: true, metaTags: metaTags });
});

app.get('/my-files', isAuthenticated, (req, res) => {
    db.all('SELECT * FROM files WHERE owner = ? ORDER BY originalName ASC', [req.session.user.username], (err, userFiles) => {
        if (err) { console.error(err); return res.status(500).send("Database error."); }
        
        if(req.query.upload === 'success' && !req.session.flash) {
            req.session.flash = { type: 'success', message: 'File uploaded successfully!' };
        }
        const flash = res.locals.flash ? `<div class="flash-message flash-${res.locals.flash.type}">${res.locals.flash.message}</div>` : '';

        const fileListHtml = userFiles.length > 0 ? `<ul class="file-list">${userFiles.map(file => `
            <li class="file-item glass-panel">
                <div class="file-details">
                    <a href="/share/${file.id}" class="file-name" title="${file.originalName}">${file.originalName}</a>
                    <div class="file-meta">Size: ${formatBytes(file.size)}</div>
                </div>
                <div class="file-actions">
                    <button type="button" class="btn btn-secondary copy-link-btn" data-link="${DOMAIN}/share/${file.id}">Copy Link</button>
                    <a href="/download/${file.id}" class="btn btn-primary">Download</a>
                    <form action="/my-files/delete" method="post" style="margin:0;"><input type="hidden" name="id" value="${file.id}"><button type="submit" class="btn btn-danger">Delete</button></form>
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
                    </div>
                    <input type="file" name="sharedFile" id="file-input" class="file-input-hidden" required>
                    <div class="progress-bar-container" id="progress-bar-container"><div id="progress-bar"></div></div>
                    <button type="submit" class="btn btn-primary" style="align-self: flex-start; margin-top: 20px;">Upload File</button>
                </form>
            </div>`;
        
        renderPage(res, `<main><h1 class="page-title">My Vault</h1>${flash}${fileListHtml}${uploadForm}</main>`, { title: 'My Vault' });
    });
});

app.post('/upload', isAuthenticated, upload.single('sharedFile'), (req, res) => {
    if (!req.file) return res.status(400).send("No file uploaded.");
    const id = crypto.randomBytes(4).toString('hex');
    const { originalname, filename, size } = req.file;
    db.run('INSERT INTO files (id, owner, originalName, storedName, size) VALUES (?, ?, ?, ?, ?)', [id, req.session.user.username, originalname, filename, size], (err) => {
        if (err) { console.error(err); return res.status(500).send("Error saving file info."); }
        res.status(200).send("Upload successful");
    });
});

app.post('/my-files/delete', isAuthenticated, (req, res) => {
    db.get('SELECT storedName FROM files WHERE id = ? AND owner = ?', [req.body.id, req.session.user.username], (err, row) => {
        if (err || !row) return res.status(404).send('File not found or permission denied.');
        fs.unlink(path.join(UPLOAD_DIR, row.storedName), () => db.run('DELETE FROM files WHERE id = ?', [req.body.id], () => res.redirect('/my-files')));
    });
});

app.get('/share/:id', (req, res) => {
    const { id } = req.params; 
    db.get('SELECT * FROM files WHERE id = ?', [id], (err, file) => {
        if (err || !file) {
            return renderPage(res, `<main class="centered-container"><div class="glass-panel text-center"><h1 class="page-title">404</h1><h2>File Not Found</h2></div></main>`, { title: 'Not Found', hideNav: true });
        }
        
        const fileUrl = `${DOMAIN}/download/${file.id}`;
        const mimeType = mime.lookup(file.originalName);
        let metaTags = `<meta property="og:title" content="${file.originalName}"><meta name="theme-color" content="#a855f7"><meta property="og:description" content="Size: ${formatBytes(file.size)}">`;
        
        if (mimeType && mimeType.startsWith('image/')) {
            metaTags += `<meta property="og:image" content="${fileUrl}"><meta name="twitter:card" content="summary_large_image">`;
        } else if (mimeType && mimeType.startsWith('video/')) {
            metaTags += `<meta property="og:video" content="${fileUrl}"><meta property="og:video:type" content="${mimeType}">`;
        }

        let embedContent;
        if (file.embed_type === 'direct') {
            if (mimeType && mimeType.startsWith('image/')) {
                embedContent = `<img src="${fileUrl}" style="max-width: 100%; border-radius: 12px;">`;
            } else if (mimeType && mimeType.startsWith('video/')) {
                embedContent = `<video controls src="${fileUrl}" style="max-width: 100%; border-radius: 12px;"></video>`;
            } else if (mimeType && mimeType.startsWith('audio/')) {
                embedContent = `<audio controls src="${fileUrl}" style="width: 100%;"></audio>`;
            } else {
                embedContent = `<p>Direct preview is not available.</p><a href="${fileUrl}" class="btn btn-primary">Download File</a>`;
            }
        } else {
            embedContent = `<div class="share-card"><div class="share-details"><p class="share-filename" title="${file.originalName}">${file.originalName}</p><p class="share-meta">Owner: ${file.owner} &bull; Size: ${formatBytes(file.size)}</p></div><a href="${fileUrl}" class="btn btn-primary">Download</a></div>`;
        }
        const body = `<main class="centered-container"><div class="glass-panel" style="width:100%;max-width:600px;"><h2 class="section-header">Shared File</h2>${embedContent}</div></main>`;
        renderPage(res, body, { title: `Share - ${file.originalName}`, hideNav: true, metaTags: metaTags });
    });
});

app.get('/download/:id', (req, res) => {
    db.get('SELECT storedName, originalName FROM files WHERE id = ?', [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).send('File not found.');
        res.download(path.join(UPLOAD_DIR, row.storedName), row.originalName);
    });
});

// --- 6. Authentication Routes ---
app.get('/register', (req, res) => {
    if (req.session.user) return res.redirect('/my-files');
    const flash = res.locals.flash ? `<p class="flash-message flash-error">${res.locals.flash.message}</p>` : '';
    const bodyContent = `<main class="centered-container"><div class="glass-panel" style="max-width:450px;width:100%;"><form class="fingerprint-form" action="/register" method="post"><h1 class="page-title text-center">Create Account</h1>${flash}<input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><input type="password" name="confirmPassword" placeholder="Confirm Password" required><button type="submit" class="btn btn-primary">Register</button><p class="fine-print" style="margin-top:20px;">Have an account already? <a href="/login">Login here</a></p></form></div></main>`;
    renderPage(res, bodyContent, { title: 'Register', hideNav: true });
});

app.post('/register', (req, res) => {
    const { username, password, confirmPassword, fingerprint } = req.body;
    if (!username || !password) {
        req.session.flash = { type: 'error', message: 'Username and password are required.'};
        return res.redirect('/register');
    }
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
            db.run('INSERT INTO users (username, password, role, last_fingerprint) VALUES (?, ?, ?, ?)', [username, hashedPassword, role, fingerprint], () => res.redirect('/login'));
        });
    });
});

app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/my-files');
    const flash = res.locals.flash ? `<p class="flash-message flash-error">${res.locals.flash.message}</p>` : '';
    const bodyContent = `<main class="centered-container"><div class="glass-panel" style="max-width:450px;width:100%;"><form class="fingerprint-form" action="/login" method="post"><h1 class="page-title text-center">Welcome Back</h1>${flash}<input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><button type="submit" class="btn btn-primary">Login</button><p class="fine-print" style="margin-top:20px;">Don't have an account? <a href="/register">Register here</a></p></form></div></main>`;
    renderPage(res, bodyContent, { title: 'Login', hideNav: true });
});

app.post('/login', (req, res) => {
    const { username, password, fingerprint } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (user && await bcrypt.compare(password, user.password)) {
            if (user.status === 'banned') {
                return renderPage(res, `<main class="centered-container"><div class="glass-panel text-center"><h1 class="page-title">🚫 Account Banned</h1><p>${user.ban_reason || 'No reason provided.'}</p></div></main>`, { title: 'Account Banned', hideNav: true });
            }
            db.run('UPDATE users SET last_login_ip = ?, last_fingerprint = ? WHERE username = ?', [req.ip, fingerprint, username]);
            req.session.user = { id: user.id, username: user.username, role: user.role };
            res.redirect('/my-files');
        } else {
            req.session.flash = { type: 'error', message: 'Invalid username or password.' };
            res.redirect('/login');
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// --- 7. Settings Routes ---
app.get('/settings', isAuthenticated, (req, res) => {
    const flash = res.locals.flash ? `<div class="flash-message flash-${res.locals.flash.type}">${res.locals.flash.message}</div>` : '';
    const bodyContent = `
        <main>
            <h1 class="page-title">Settings</h1>
            ${flash}
            <div class="glass-panel" style="margin-bottom: 30px;">
                <h2 class="section-header">Change Username</h2>
                <form action="/settings/username" method="post">
                    <input type="text" name="newUsername" placeholder="New Username" required>
                    <button type="submit" class="btn btn-primary" style="align-self: flex-start;">Save Username</button>
                </form>
            </div>
            <div class="glass-panel">
                <h2 class="section-header">Change Password</h2>
                <form action="/settings/password" method="post">
                    <input type="password" name="currentPassword" placeholder="Current Password" required>
                    <input type="password" name="newPassword" placeholder="New Password" required>
                    <button type="submit" class="btn btn-primary" style="align-self: flex-start;">Save Password</button>
                </form>
            </div>
        </main>`;
    renderPage(res, bodyContent, { title: 'Settings' });
});

app.post('/settings/username', isAuthenticated, (req, res) => {
    const { newUsername } = req.body;
    if (newUsername.toLowerCase() === req.session.user.username.toLowerCase()) {
        req.session.flash = { type: 'error', message: 'New username cannot be the same as the current one.' };
        return res.redirect('/settings');
    }
    db.get('SELECT id FROM users WHERE username = ?', [newUsername], (err, row) => {
        if (row) {
            req.session.flash = { type: 'error', message: 'Username is already taken.' };
            return res.redirect('/settings');
        }
        db.run('UPDATE files SET owner = ? WHERE owner = ?', [newUsername, req.session.user.username]);
        db.run('UPDATE users SET username = ? WHERE id = ?', [newUsername, req.session.user.id], () => {
            req.session.user.username = newUsername;
            req.session.flash = { type: 'success', message: 'Username updated successfully!' };
            res.redirect('/settings');
        });
    });
});

app.post('/settings/password', isAuthenticated, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    db.get('SELECT password FROM users WHERE id = ?', [req.session.user.id], async (err, user) => {
        if (user && await bcrypt.compare(currentPassword, user.password)) {
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            db.run('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, req.session.user.id], () => {
                req.session.flash = { type: 'success', message: 'Password updated successfully!' };
                res.redirect('/settings');
            });
        } else {
            req.session.flash = { type: 'error', message: 'Incorrect current password.' };
            res.redirect('/settings');
        }
    });
});

// --- 8. Admin Routes ---
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT * FROM users", [], (err, users) => {
        db.all('SELECT * FROM files', [], (err, allFiles) => {
            const userListHtml = `<ul class="file-list">${users.map(user => {
                const isBanned = user.status === 'banned';
                let actionsHtml = '';
                if (user.username !== req.session.user.username) {
                    actionsHtml += isBanned ? `<form action="/admin/users/status" method="post" style="margin:0;"><input type="hidden" name="username" value="${user.username}"><input type="hidden" name="action" value="unban"><button type="submit" class="btn btn-success">Unban</button></form>`
                                           : `<button type="button" class="btn btn-danger open-ban-modal" data-username="${user.username}">Ban</button>`;
                    if (user.role !== 'admin') actionsHtml += `<form action="/admin/users/promote" method="post" style="margin:0;"><input type="hidden" name="username" value="${user.username}"><button type="submit" class="btn btn-secondary">Promote</button></form>`;
                    actionsHtml += `<form action="/admin/users/delete" method="post" onsubmit="return confirm('Are you sure? This will delete the user and all their files permanently.')" style="margin:0;"><input type="hidden" name="username" value="${user.username}"><button type="submit" class="btn btn-danger">Delete</button></form>`;
                } else {
                    actionsHtml = '<span style="color:var(--text-secondary)">(This is you)</span>';
                }
                return `<li class="file-item glass-panel"><div class="file-details"><span class="file-name">${user.username}</span><div class="file-meta">Role: ${user.role} &bull; IP: ${user.last_login_ip || 'N/A'}</div></div><div class="file-actions">${actionsHtml}</div></li>`;
            }).join('')}</ul>`;

            const fileListHtml = `<ul class="file-list">${allFiles.map(file => `
                <li class="file-item glass-panel"><div class="file-details"><a href="/share/${file.id}" class="file-name" title="${file.originalName}">${file.originalName}</a><div class="file-meta">Owner: ${file.owner} &bull; Size: ${formatBytes(file.size)}</div></div><div class="file-actions"><form action="/admin/files/delete" method="post" style="margin:0;"><input type="hidden" name="id" value="${file.id}"><button type="submit" class="btn btn-danger">Delete</button></form></div></li>`
            ).join('')}</ul>`;

            renderPage(res, `<main><h1 class="page-title">Admin Panel</h1><div class="glass-panel" style="margin-bottom: 30px;"><h2 class="section-header">Manage Users</h2>${userListHtml}</div><div class="glass-panel"><h2 class="section-header">Manage All Files</h2>${fileListHtml}</div></main>`, { title: 'Admin Panel' });
        });
    });
});

app.post('/admin/users/status', isAuthenticated, isAdmin, (req, res) => {
    const { username, action, reason } = req.body;
    db.get('SELECT last_login_ip, last_fingerprint FROM users WHERE username = ?', [username], (err, user) => {
        if (action === 'ban' && user) {
            if (user.last_login_ip) db.run('INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)', [user.last_login_ip]);
            if (user.last_fingerprint) db.run('INSERT OR IGNORE INTO banned_fingerprints (fingerprint) VALUES (?)', [user.last_fingerprint]);
        }
        const newStatus = action === 'ban' ? 'banned' : 'active';
        const banReason = action === 'ban' ? (reason || "No reason provided.") : null;
        db.run("UPDATE users SET status = ?, ban_reason = ? WHERE username = ?", [newStatus, banReason, username], () => res.redirect('/admin'));
    });
});

app.post('/admin/files/delete', isAuthenticated, isAdmin, (req, res) => {
    db.get('SELECT storedName FROM files WHERE id = ?', [req.body.id], (err, row) => {
        if (!row) return res.redirect('/admin');
        fs.unlink(path.join(UPLOAD_DIR, row.storedName), () => db.run('DELETE FROM files WHERE id = ?', [req.body.id], () => res.redirect('/admin')));
    });
});

app.post('/admin/users/promote', isAuthenticated, isAdmin, (req, res) => {
    db.run("UPDATE users SET role = 'admin' WHERE username = ?", [req.body.username], () => res.redirect('/admin'));
});

app.post('/admin/users/delete', isAuthenticated, isAdmin, (req, res) => {
    db.all('SELECT storedName FROM files WHERE owner = ?', [req.body.username], (err, files) => {
        files.forEach(file => fs.unlink(path.join(UPLOAD_DIR, file.storedName), ()=>{}));
        db.run('DELETE FROM files WHERE owner = ?', [req.body.username], () => db.run('DELETE FROM users WHERE username = ?', [req.body.username], () => res.redirect('/admin')));
    });
});

// --- 9. Start Server ---
app.listen(PORT, () => console.log(`🚀 Server is running on port ${PORT}`));