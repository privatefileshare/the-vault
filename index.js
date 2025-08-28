require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

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
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', last_login_ip TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, owner TEXT NOT NULL, originalName TEXT NOT NULL, storedName TEXT NOT NULL, size INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY NOT NULL, banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
});

// --- 2. Middleware ---
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use((req, res, next) => {
    const userIp = req.ip;
    db.get('SELECT ip FROM banned_ips WHERE ip = ?', [userIp], (err, row) => {
        if (err) return next();
        if (row) {
            const bodyContent = `<main><h2 class="section-header">Access Denied</h2><p style="text-align: center; font-size: 1.1rem;">Your IP address has been banned.</p></main>`;
            return renderPage(res, bodyContent, { title: 'Access Denied' });
        }
        next();
    });
});

app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use((req, res, next) => {
    res.locals.user = req.session.user;
    if (req.session.flash) {
        res.locals.flash = req.session.flash;
        delete req.session.flash;
    }
    next();
});

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const uniquePrefix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniquePrefix + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// --- 3. Helper Functions & Middleware ---
function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}
const isAuthenticated = (req, res, next) => {
    if (!req.session.user) return res.redirect('/login');
    next();
};
const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).send('<h1>403 Forbidden</h1>');
};

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

    // --- UPDATED to include dynamic meta tags ---
    res.send(`
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${options.title || 'The Vault'}</title>
        <meta name="description" content="${options.description || 'Secure, private file sharing.'}">
        <link rel="icon" type="image/png" href="/favicon.png">

        <meta property="og:title" content="${options.title || 'The Vault'}">
        <meta property="og:description" content="${options.description || 'Secure, private file sharing.'}">
        <meta property="og:image" content="${options.image || `${DOMAIN}/logo.png`}">
        <meta property="og:url" content="${options.url || DOMAIN}">
        <meta property="og:type" content="website">
        <meta name="theme-color" content="#a855f7">

        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            /* All CSS from previous steps is unchanged */
            :root { --primary-purple: #a855f7; /* ... etc */ }
            body { /* ... */ }
        </style>
        </head><body>
            <div class="container">
                <nav class="navbar glass-panel">${authLinks}</nav>
                ${bodyContent}
                <footer><p>&copy; ${new Date().getFullYear()} The Vault. All rights reserved.</p></footer>
            </div>
            ${options.extraScript || ''}
        </body></html>`);
}

// --- 5. Main Routes ---
app.get('/', (req, res) => {
    const bodyContent = `<main class="text-center"><h1 class="page-title" style="text-align:center;">The Vault</h1><p>Your personal corner of the cloud, secured and styled.</p><p style="margin-top: 40px;">${req.session.user ? '<a href="/my-files" class="btn btn-primary">Enter My Vault</a>' : '<a href="/login" class="btn btn-primary">Login to Enter</a>'}</p></main>`;
    renderPage(res, bodyContent, {
        title: 'The Vault - Secure File Sharing',
        description: 'A modern, private file hosting application with a liquid glass UI.',
        url: DOMAIN
    });
});

app.get('/my-files', isAuthenticated, (req, res) => {
    // This route is unchanged, the share links it generates will now have rich embeds
    db.all('SELECT * FROM files WHERE owner = ? ORDER BY originalName ASC', [req.session.user.username], (err, userFiles) => {
        if (err) return res.status(500).send("Database error.");
        const fileListHtml = `...`; // Unchanged
        const uploadForm = `...`; // Unchanged
        renderPage(res, `<main><h1 class="page-title">My Vault</h1>${fileListHtml}${uploadForm}</main>`);
    });
});

app.post('/upload', (req, res) => { /* Unchanged */ });
app.post('/my-files/delete', (req, res) => { /* Unchanged */ });

// --- UPDATED share link route ---
app.get('/share/:id', (req, res) => {
    db.get('SELECT * FROM files WHERE id = ?', [req.params.id], (err, fileRecord) => {
        if (err || !fileRecord) {
            const bodyContent = `<main><h2 class="section-header">404 - Not Found</h2><p style="text-align: center;">The file you are looking for does not exist or has been deleted.</p></main>`;
            return renderPage(res, bodyContent, { title: 'File Not Found' });
        }
        
        // This is the new landing page for the shared file
        const bodyContent = `
            <main class="text-center">
                <h1 class="page-title" style="text-align:center;">Download File</h1>
                <div class="glass-panel" style="padding: 25px;">
                    <p style="font-size: 1.2rem; color: var(--text-primary);">${fileRecord.originalName}</p>
                    <p style="color: var(--text-secondary);">Size: ${formatBytes(fileRecord.size)}</p>
                    <a href="/download/${fileRecord.id}" class="btn btn-primary" style="margin-top: 20px;">Download Now</a>
                </div>
            </main>
        `;

        // This script will auto-start the download for regular users
        const extraScript = `
            <script>
                setTimeout(() => {
                    window.location.href = "/download/${fileRecord.id}";
                }, 1000);
            </script>
        `;
        
        renderPage(res, bodyContent, {
            title: `Download ${fileRecord.originalName}`,
            description: `File uploaded to The Vault. Size: ${formatBytes(fileRecord.size)}.`,
            url: `${DOMAIN}/share/${fileRecord.id}`,
            extraScript: extraScript
        });
    });
});

// --- NEW download-only route ---
app.get('/download/:id', (req, res) => {
    db.get('SELECT * FROM files WHERE id = ?', [req.params.id], (err, fileRecord) => {
        if (err || !fileRecord) return res.status(404).send('File not found.');
        res.download(path.join(UPLOAD_DIR, fileRecord.storedName), fileRecord.originalName);
    });
});


// --- 6. Authentication Routes ---
// ... All auth routes are unchanged ...

// --- 7. Admin Routes ---
// ... All admin routes are unchanged ...

// --- 8. Start Server ---
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});