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

// Serve static files like logos and favicons from the 'public' folder
app.use(express.static('public'));

app.use((req, res, next) => {
    const userIp = req.ip;
    db.get('SELECT ip FROM banned_ips WHERE ip = ?', [userIp], (err, row) => {
        if (err) {
            console.error("IP ban check database error:", err);
            return next();
        }
        if (row) {
            const bodyContent = `<main><h2 class="section-header">Access Denied</h2><p style="text-align: center; font-size: 1.1rem;">Your IP address has been banned.</p></main>`;
            return renderPage(res, bodyContent);
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
function renderPage(res, bodyContent) {
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
        <title>The Vault</title>
        <link rel="icon" type="image/png" href="/favicon.png">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary-purple: #a855f7; --glow-purple: rgba(168, 85, 247, 0.5);
                --text-primary: #e5e7eb; --text-secondary: #9ca3af;
                --glass-bg: rgba(255, 255, 255, 0.05); --glass-border: rgba(255, 255, 255, 0.1);
                --danger-color: #f43f5e; --danger-glow: rgba(244, 63, 94, 0.5);
                --success-color: #28a745; --success-glow: rgba(40, 167, 69, 0.5);
            }
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
            input[type="text"], input[type="password"], input[type="file"] { background-color: var(--glass-bg); color: var(--text-primary); border: 1px solid var(--glass-border); padding: 12px; border-radius: 8px; font-size: 1em; transition: all 0.2s ease; backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px); }
            .input-error { border-color: var(--danger-color) !important; box-shadow: 0 0 10px 1px var(--danger-glow) !important; }
            .error-message { color: var(--danger-color); font-size: 0.9rem; margin-top: -5px; text-align: left; }
            .share-link-container { display: flex; gap: 10px; margin-top: 15px; border-top: 1px solid var(--glass-border); padding-top: 15px; }
            .share-link-input { flex-grow: 1; background-color: rgba(0,0,0,0.4); border: 1px solid var(--glass-border); color: var(--text-secondary); padding: 8px 10px; border-radius: 6px; font-family: monospace; }
            .copy-button { background-color: rgba(255, 255, 255, 0.1); color: white; border: none; padding: 8px 15px; border-radius: 6px; cursor: pointer; } .copy-button:hover { background-color: var(--primary-purple); }
            
            @media (max-width: 768px) {
                body { padding: 20px 10px; }
                .page-title { font-size: 2rem; }
                .file-main-content { flex-direction: column; align-items: flex-start; gap: 15px; }
                .file-actions { margin-left: 0; width: 100%; justify-content: flex-end; }
                .file-item { padding: 15px; }
                .file-size { padding-right: 0; margin-left: 10px; order: -1; align-self: flex-end; }
                .file-details { width: 100%; }
                .navbar { flex-wrap: wrap; }
            }
        </style>
        </head><body>
            <div class="container">
                <nav class="navbar glass-panel">${authLinks}</nav>
                ${bodyContent}
                <footer><p>&copy; ${new Date().getFullYear()} The Vault. All rights reserved.</p></footer>
            </div>
            <script>
                document.addEventListener('click', function(event) {
                    if (event.target.classList.contains('copy-button')) {
                        const input = event.target.previousElementSibling;
                        input.select();
                        input.setSelectionRange(0, 99999);
                        document.execCommand('copy');
                        event.target.textContent = 'Copied!';
                        setTimeout(() => { event.target.textContent = 'Copy'; }, 2000);
                    }
                });
            </script>
        </body></html>`);
}

// --- 5. Main Routes ---
app.get('/', (req, res) => {
    const bodyContent = `
        <main class="text-center">
            <img src="/logo.png" alt="The Vault Logo" style="max-width: 150px; margin-bottom: 20px;">
            <h1 class="page-title" style="text-align:center;">The Vault</h1>
            <p>Your personal corner of the cloud, secured and styled.</p>
            <p style="margin-top: 40px;">
                ${req.session.user ? '<a href="/my-files" class="btn btn-primary">Enter My Vault</a>' : '<a href="/login" class="btn btn-primary">Login to Enter</a>'}
            </p>
        </main>`;
    renderPage(res, bodyContent);
});

app.get('/my-files', isAuthenticated, (req, res) => {
    db.all('SELECT * FROM files WHERE owner = ? ORDER BY originalName ASC', [req.session.user.username], (err, userFiles) => {
        if (err) return res.status(500).send("Database error.");
        
        const fileListHtml = userFiles.length > 0 ? '<ul class="file-list">' + userFiles.map(f => {
            return `
                <li class="file-item">
                    <div class="file-main-content">
                        <div class="file-details">
                            <span class="file-name">${f.originalName}</span>
                            <span class="file-description">Your private file.</span>
                        </div>
                        <span class="file-size">${formatBytes(f.size)}</span>
                        <div class="file-actions">
                             <a href="/share/${f.id}" class="btn btn-primary">Download</a>
                             <form action="/my-files/delete" method="post" style="display:inline; margin:0; padding:0; background:none;">
                                 <input type="hidden" name="fileId" value="${f.id}">
                                 <button type="submit" class="btn btn-danger">Delete</button>
                             </form>
                        </div>
                    </div>
                    <div class="share-link-container">
                        <input type="text" readonly class="share-link-input" value="${DOMAIN}/share/${f.id}">
                        <button class="copy-button">Copy</button>
                    </div>
                </li>`;
        }).join('') + '</ul>' : '<p style="text-align:center;">Your vault is empty. Upload a file to get started.</p>';
        
        const uploadForm = `<h2 class="section-header">Upload New File</h2><form action="/upload" method="post" enctype="multipart/form-data" class="glass-panel"><input type="file" name="sharedFile" required><input type="submit" class="btn btn-primary" value="Upload"></form>`;
        renderPage(res, `<main><h1 class="page-title">My Vault</h1>${fileListHtml}${uploadForm}</main>`);
    });
});

// All other routes... (unchanged from the last complete script)
app.post('/upload', isAuthenticated, upload.single('sharedFile'), (req, res) => {
    if (!req.file) return res.status(400).send("No file uploaded.");
    const newFile = { id: crypto.randomBytes(16).toString('hex'), owner: req.session.user.username, originalName: req.file.originalname, storedName: req.file.filename, size: req.file.size };
    db.run('INSERT INTO files (id, owner, originalName, storedName, size) VALUES (?, ?, ?, ?, ?)', [newFile.id, newFile.owner, newFile.originalName, newFile.storedName, newFile.size], (err) => {
        if (err) return res.status(500).send("Could not save file information.");
        res.redirect('/my-files');
    });
});

app.post('/my-files/delete', isAuthenticated, (req, res) => {
    const { fileId } = req.body;
    db.get('SELECT * FROM files WHERE id = ? AND owner = ?', [fileId, req.session.user.username], (err, fileRecord) => {
        if (err || !fileRecord) return res.status(403).send("File not found or you don't have permission.");
        const filePath = path.join(UPLOAD_DIR, fileRecord.storedName);
        fs.unlink(filePath, err => {
            if (err) return res.status(500).send("Could not delete file from disk.");
            db.run('DELETE FROM files WHERE id = ?', [fileId], (err) => {
                if (err) return res.status(500).send("Could not delete file record.");
                res.redirect('/my-files');
            });
        });
    });
});

app.get('/share/:id', (req, res) => {
    db.get('SELECT * FROM files WHERE id = ?', [req.params.id], (err, fileRecord) => {
        if (err || !fileRecord) return res.status(404).send('<h1>404 Not Found</h1>');
        res.download(path.join(UPLOAD_DIR, fileRecord.storedName), fileRecord.originalName);
    });
});

app.get('/register', (req, res) => {
    const flash = res.locals.flash || {};
    const bodyContent = `<h2 class="section-header">Create Account</h2><form action="/register" method="post" class="glass-panel"><input type="text" name="username" placeholder="Username" required class="${flash.field === 'username' ? 'input-error' : ''}" value="${flash.inputValue || ''}">${flash.field === 'username' ? `<div class="error-message">${flash.message}</div>` : ''}<input type="password" name="password" placeholder="Password" required><input type="submit" class="btn btn-primary" value="Register"></form>`;
    renderPage(res, bodyContent);
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
        if (err) return res.status(500).send("Database error.");
        if (row) {
            req.session.flash = { type: 'error', message: 'That username is already taken.', field: 'username', inputValue: username };
            return res.redirect('/register');
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        db.get('SELECT COUNT(*) as count FROM users', [], (err, result) => {
            if (err) return res.status(500).send("Database error.");
            const role = result.count === 0 ? 'admin' : 'user';
            db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], (err) => {
                if (err) return res.status(500).send("Could not register user.");
                res.redirect('/login');
            });
        });
    });
});

app.get('/login', (req, res) => {
    const flash = res.locals.flash || {};
    const bodyContent = `<h2 class="section-header">Welcome Back</h2><form action="/login" method="post" class="glass-panel"><input type="text" name="username" placeholder="Username" required class="${flash.field === 'all' ? 'input-error' : ''}" value="${flash.inputValue || ''}"><input type="password" name="password" placeholder="Password" required class="${flash.field === 'all' ? 'input-error' : ''}">${flash.field === 'all' ? `<div class="error-message">${flash.message}</div>` : ''}<input type="submit" class="btn btn-primary" value="Login"></form>`;
    renderPage(res, bodyContent);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) return res.status(500).send("Database error.");
        if (user && await bcrypt.compare(password, user.password)) {
            if (user.status === 'banned') {
                const bodyContent = `<main><h2 class="section-header">Access Denied</h2><p style="text-align: center; font-size: 1.1rem;">Your account has been banned by an administrator.</p></main>`;
                return renderPage(res, bodyContent);
            }
            const userIp = req.ip;
            db.run('UPDATE users SET last_login_ip = ? WHERE username = ?', [userIp, username]);
            req.session.user = { username: user.username, role: user.role };
            res.redirect('/my-files');
        } else {
            req.session.flash = { type: 'error', message: 'Invalid username or password.', field: 'all', inputValue: username };
            res.redirect('/login');
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    db.all("SELECT * FROM users", [], (err, users) => {
        if (err) return res.status(500).send("Database error fetching users.");
        db.all('SELECT * FROM files', [], (err, allFiles) => {
            if (err) return res.status(500).send("Database error fetching files.");
            const userListHtml = users.length > 0 ? '<ul class="file-list">' + users.map(user => {
                const isBanned = user.status === 'banned';
                const action = isBanned ? 'unban' : 'ban';
                const buttonClass = isBanned ? 'btn-success' : 'btn-danger';
                let actionsHtml = '';
                if (user.username !== req.session.user.username) {
                    actionsHtml += `<form action="/admin/users/status" method="post" style="margin:0; padding:0; background:none;"><input type="hidden" name="username" value="${user.username}"><input type="hidden" name="action" value="${action}"><button type="submit" class="btn ${buttonClass}">${action.charAt(0).toUpperCase() + action.slice(1)}</button></form>`;
                    if (user.role !== 'admin') {
                        actionsHtml += `<form action="/admin/users/promote" method="post" onsubmit="return confirm('Are you sure you want to promote ${user.username} to an admin?');" style="margin:0; padding:0; background:none;"><input type="hidden" name="username" value="${user.username}"><button type="submit" class="btn btn-secondary">Promote</button></form>`;
                    }
                    actionsHtml += `<form action="/admin/users/delete" method="post" onsubmit="return confirm('Are you sure you want to permanently delete user ${user.username} and all their files? This cannot be undone.');" style="margin:0; padding:0; background:none;"><input type="hidden" name="username" value="${user.username}"><button type="submit" class="btn btn-danger">Delete</button></form>`;
                } else {
                    actionsHtml = '<span style="color: var(--text-secondary);">(This is you)</span>';
                }
                return `<li class="file-item glass-panel"><div class="file-details"><span class="file-name">${user.username}</span><span class="file-description">Role: <strong>${user.role}</strong> | Status: <strong>${user.status}</strong></span></div><div class="file-actions">${actionsHtml}</div></li>`;
            }).join('') + '</ul>' : '<p style="text-align:center;">No users to manage.</p>';
            const fileListHtml = allFiles.length > 0 ? '<ul class="file-list">' + allFiles.map(f => `<li class="file-item glass-panel"><div class="file-main-content"><div class="file-details"><span class="file-name">${f.originalName}</span><span class="file-description">Uploaded by ${f.owner}</span></div><span class="file-size">${formatBytes(f.size)}</span><div class="file-actions"><form action="/admin/files/delete" method="post" style="display:inline; margin:0; padding:0; background:none;"><input type="hidden" name="fileId" value="${f.id}"><button type="submit" class="btn btn-danger">Delete</button></form></div></div></li>`).join('') + '</ul>' : '<p style="text-align:center;">No files to manage.</p>';
            const bodyContent = `<main><div class="header"><h1>Admin Panel</h1></div><h2 class="section-header">Manage Users</h2>${userListHtml}<h2 class="section-header" style="margin-top: 40px;">Manage Files</h2>${fileListHtml}</main>`;
            renderPage(res, bodyContent);
        });
    });
});

app.post('/admin/files/delete', isAuthenticated, isAdmin, (req, res) => {
    const { fileId } = req.body;
    db.get('SELECT storedName FROM files WHERE id = ?', [fileId], (err, fileRecord) => {
        if (err || !fileRecord) return res.status(404).send("File not found.");
        const filePath = path.join(UPLOAD_DIR, fileRecord.storedName);
        fs.unlink(filePath, err => {
            if (err) return res.status(500).send("Could not delete file from disk.");
            db.run('DELETE FROM files WHERE id = ?', [fileId], (err) => {
                if (err) return res.status(500).send("Could not delete file record.");
                res.redirect('/admin');
            });
        });
    });
});

app.post('/admin/users/status', isAuthenticated, isAdmin, (req, res) => {
    const { username, action } = req.body;
    const newStatus = action === 'ban' ? 'banned' : 'active';
    if (username === req.session.user.username) { return res.redirect('/admin'); }
    
    if (action === 'ban') {
        db.get('SELECT last_login_ip FROM users WHERE username = ?', [username], (err, user) => {
            if (user && user.last_login_ip) {
                db.run('INSERT OR IGNORE INTO banned_ips (ip) VALUES (?)', [user.last_login_ip], (err) => {
                    if (err) console.error("Failed to ban IP:", err);
                    else console.log(`IP address ${user.last_login_ip} banned for user ${username}.`);
                });
            }
        });
    }
    
    db.run("UPDATE users SET status = ? WHERE username = ?", [newStatus, username], (err) => {
        if (err) return res.status(500).send("Database error updating user status.");
        res.redirect('/admin');
    });
});

app.post('/admin/users/promote', isAuthenticated, isAdmin, (req, res) => {
    const { username } = req.body;
    db.run("UPDATE users SET role = 'admin' WHERE username = ?", [username], (err) => {
        if (err) return res.status(500).send("Database error promoting user.");
        res.redirect('/admin');
    });
});

app.post('/admin/users/delete', isAuthenticated, isAdmin, (req, res) => {
    const { username } = req.body;
    if (username === req.session.user.username) { return res.redirect('/admin'); }
    db.all('SELECT storedName FROM files WHERE owner = ?', [username], (err, files) => {
        if (err) return res.status(500).send("Error finding user's files.");
        const deletionPromises = files.map(file => new Promise((resolve) => {
            fs.unlink(path.join(UPLOAD_DIR, file.storedName), (err) => {
                if (err) console.error(`Failed to delete ${file.storedName}:`, err);
                resolve();
            });
        }));
        Promise.all(deletionPromises).then(() => {
            db.run('DELETE FROM files WHERE owner = ?', [username], (err) => {
                if (err) return res.status(500).send("Error deleting user's file records.");
                db.run('DELETE FROM users WHERE username = ?', [username], (err) => {
                    if (err) return res.status(500).send("Error deleting user.");
                    res.redirect('/admin');
                });
            });
        });
    });
});

// --- 8. Start Server ---
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});