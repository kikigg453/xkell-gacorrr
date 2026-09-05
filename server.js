const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const axios = require('axios');
const Go = require('@xof/fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ KONFIGURASI ============
const CONFIG = {
    server1: {
        base: 'https://restapidhan.vercel.app',
        apikey: 'freeapikeydhan26',
        name: '🖥️ Server 1 - RestApi Dhan'
    },
    server2: {
        baseUrl: 'https://am.yappi.my.id',
        cookieApi: 'https://am.yappi.my.id/api/cookie',
        sendApi: 'https://am.yappi.my.id/api/send',
        verifyApi: 'https://am.yappi.my.id/api/verify',
        name: '🌐 Server 2 - AM Yappi'
    },
    antiSpam: {
        maxRegistrations: 3,
        timeWindow: 3600000,
        banDuration: 86400000
    }
};

// ============ DATABASE ============
const DB = {
    users: [
        { 
            username: 'KELL', 
            password: '9089', 
            role: 'owner',
            limits: { server1: 999, server2: 999 },
            used: { server1: 0, server2: 0 }
        }
    ],
    broadcasts: [],
    settings: {
        server1: true,
        server2: true
    },
    ipTracker: {},
    bannedIPs: {},
    redeemCodes: []
};

// ============ MIDDLEWARE ============
app.use(cors({ origin: '*', credentials: true }));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: 'xkelzz-am-secret-2024',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: 'lax'
    }
}));

// ============ IP DETECTION ============
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress || 
           req.ip || 
           '127.0.0.1';
}

// ============ ANTI-SPAM ============
function checkIPBan(ip) {
    const banned = DB.bannedIPs[ip];
    if (banned) {
        if (Date.now() < banned.bannedUntil) {
            return { 
                banned: true, 
                reason: banned.reason || 'Melanggar aturan penggunaan', 
                until: banned.bannedUntil 
            };
        } else {
            delete DB.bannedIPs[ip];
            delete DB.ipTracker[ip];
            return { banned: false };
        }
    }
    return { banned: false };
}

function trackRegistration(ip) {
    if (!DB.ipTracker[ip]) {
        DB.ipTracker[ip] = {
            registrations: [],
            bannedUntil: null,
            reason: null
        };
    }

    const tracker = DB.ipTracker[ip];
    const now = Date.now();
    const timeWindow = CONFIG.antiSpam.timeWindow;
    const maxReg = CONFIG.antiSpam.maxRegistrations;

    tracker.registrations = tracker.registrations.filter(t => now - t < timeWindow);

    if (tracker.bannedUntil && now < tracker.bannedUntil) {
        return { 
            allowed: false, 
            banned: true, 
            reason: tracker.reason || 'Terlalu banyak registrasi dari IP ini',
            until: tracker.bannedUntil
        };
    }

    if (tracker.bannedUntil && now >= tracker.bannedUntil) {
        tracker.bannedUntil = null;
        tracker.reason = null;
        tracker.registrations = [];
    }

    if (tracker.registrations.length >= maxReg) {
        const banDuration = CONFIG.antiSpam.banDuration;
        tracker.bannedUntil = now + banDuration;
        tracker.reason = `Terlalu banyak registrasi dalam waktu singkat (${maxReg} kali dalam 1 jam)`;
        
        DB.bannedIPs[ip] = {
            bannedUntil: tracker.bannedUntil,
            reason: tracker.reason
        };

        return { 
            allowed: false, 
            banned: true, 
            reason: tracker.reason,
            until: tracker.bannedUntil
        };
    }

    tracker.registrations.push(now);
    return { allowed: true };
}

function findUser(username) {
    if (!username) return null;
    return DB.users.find(u => u.username.toLowerCase() === username.toLowerCase());
}

function checkLimit(username, server) {
    const user = findUser(username);
    if (!user) return { allowed: false, message: 'User tidak ditemukan' };
    
    const limit = user.limits?.[server] || 0;
    const used = user.used?.[server] || 0;
    
    if (used >= limit && limit !== 999) {
        return { 
            allowed: false, 
            message: `⚠️ Limit ${server} habis! (${used}/${limit})`,
            limit: limit,
            used: used
        };
    }
    
    return { 
        allowed: true, 
        remaining: limit - used,
        limit: limit,
        used: used
    };
}

function useLimit(username, server) {
    const user = findUser(username);
    if (!user) return false;
    
    if (!user.used) user.used = { server1: 0, server2: 0 };
    if (!user.used[server]) user.used[server] = 0;
    
    const limit = user.limits?.[server] || 0;
    if (user.used[server] >= limit && limit !== 999) return false;
    
    user.used[server]++;
    return true;
}

function resetLimit(username, server) {
    const user = findUser(username);
    if (!user) return false;
    
    if (!user.used) user.used = { server1: 0, server2: 0 };
    user.used[server] = 0;
    return true;
}

// ============ API SERVER 1 ============
let goInstance = null;

function getGo() {
    if (!goInstance) {
        goInstance = Go.create({
            baseURL: CONFIG.server1.base,
            browser: true,
            cookieJar: true,
            keepAlive: true,
            timeout: 30000
        });
    }
    return goInstance;
}

async function server1Send(email) {
    try {
        const go = getGo();
        const { data } = await go.get('/api/am', {
            query: { 
                action: 'send', 
                apikey: CONFIG.server1.apikey, 
                email 
            }
        });
        return data;
    } catch (error) {
        throw error;
    }
}

async function server1Verify(email, url) {
    try {
        const go = getGo();
        const { data } = await go.get('/api/am', {
            query: { 
                action: 'verif', 
                apikey: CONFIG.server1.apikey, 
                email, 
                url 
            }
        });
        return data;
    } catch (error) {
        throw error;
    }
}

// ============ API SERVER 2 ============
let server2Cookie = null;

async function getServer2Cookie() {
    try {
        const res = await axios.get(CONFIG.server2.cookieApi, {
            timeout: 10000,
            headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36' }
        });
        
        if (res.data?.ok && res.data?.cookie) {
            server2Cookie = res.data.cookie;
            return server2Cookie;
        }
        throw new Error('Gagal mendapatkan session cookie');
    } catch (error) {
        throw error;
    }
}

async function server2Send(email) {
    try {
        if (!server2Cookie) await getServer2Cookie();
        
        const res = await axios.post(CONFIG.server2.sendApi, {
            email: email,
            cookie: server2Cookie
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Origin': CONFIG.server2.baseUrl,
                'Referer': `${CONFIG.server2.baseUrl}/`,
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36'
            },
            timeout: 30000
        });
        
        return res.data;
    } catch (error) {
        throw error;
    }
}

async function server2Verify(email, link) {
    try {
        if (!server2Cookie) await getServer2Cookie();
        
        const res = await axios.post(CONFIG.server2.verifyApi, {
            email: email,
            link: link,
            cookie: server2Cookie
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Origin': CONFIG.server2.baseUrl,
                'Referer': `${CONFIG.server2.baseUrl}/`,
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36'
            },
            timeout: 30000
        });
        
        return res.data;
    } catch (error) {
        throw error;
    }
}

// ============ ROUTES ============

// CHECK IP
app.post('/api/check-ip', (req, res) => {
    try {
        const ip = getClientIP(req);
        const banCheck = checkIPBan(ip);
        
        if (banCheck.banned) {
            return res.json({ 
                banned: true,
                message: `🚫 Kamu Telah Di Banned Dari Web Karena ${banCheck.reason}`,
                reason: banCheck.reason,
                until: banCheck.until
            });
        }
        
        res.json({ banned: false });
    } catch (error) {
        res.json({ banned: false });
    }
});

// LOGIN
app.post('/api/login', (req, res) => {
    try {
        const ip = getClientIP(req);
        
        const banCheck = checkIPBan(ip);
        if (banCheck.banned) {
            return res.json({ 
                success: false, 
                banned: true,
                message: `🚫 Kamu Telah Di Banned Dari Web Karena ${banCheck.reason}`,
                reason: banCheck.reason,
                until: banCheck.until
            });
        }
        
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.json({ success: false, message: '❌ Username dan password wajib diisi!' });
        }
        
        const user = findUser(username);
        
        if (!user) {
            return res.json({ success: false, message: '❌ Username tidak ditemukan!' });
        }
        
        if (user.password !== password) {
            return res.json({ success: false, message: '❌ Password salah!' });
        }
        
        req.session.user = { username: user.username, role: user.role };
        
        return res.json({ success: true, role: user.role });
    } catch (error) {
        console.error('Login error:', error);
        return res.json({ success: false, message: '❌ Terjadi kesalahan: ' + error.message });
    }
});

// REGISTER
app.post('/api/register', (req, res) => {
    try {
        const ip = getClientIP(req);
        
        const banCheck = checkIPBan(ip);
        if (banCheck.banned) {
            return res.json({ 
                success: false, 
                banned: true,
                message: `🚫 Kamu Telah Di Banned Dari Web Karena ${banCheck.reason}`,
                reason: banCheck.reason,
                until: banCheck.until
            });
        }
        
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.json({ success: false, message: '❌ Username dan password wajib diisi!' });
        }
        
        if (username.length < 3) {
            return res.json({ success: false, message: '❌ Username minimal 3 karakter!' });
        }
        
        if (password.length < 3) {
            return res.json({ success: false, message: '❌ Password minimal 3 karakter!' });
        }
        
        if (findUser(username)) {
            return res.json({ success: false, message: '❌ Username sudah terdaftar!' });
        }
        
        const trackResult = trackRegistration(ip);
        if (!trackResult.allowed) {
            return res.json({ 
                success: false, 
                banned: true,
                message: `🚫 Kamu Telah Di Banned Dari Web Karena ${trackResult.reason}`,
                reason: trackResult.reason,
                until: trackResult.until
            });
        }
        
        DB.users.push({
            username: username,
            password: password,
            role: 'user',
            limits: { server1: 1, server2: 1 },
            used: { server1: 0, server2: 0 }
        });
        
        return res.json({ success: true, message: '✅ Registrasi berhasil! Silakan login.' });
    } catch (error) {
        console.error('Register error:', error);
        return res.json({ success: false, message: '❌ Terjadi kesalahan: ' + error.message });
    }
});

// GET USER
app.get('/api/user', (req, res) => {
    try {
        if (!req.session || !req.session.user) {
            return res.json({ success: false, message: 'Not logged in' });
        }
        
        const user = findUser(req.session.user.username);
        if (!user) {
            return res.json({ success: false, message: 'User tidak ditemukan' });
        }
        
        const broadcasts = DB.broadcasts.filter(b => !b.readBy?.includes(user.username));
        const limitStatus = checkAllLimits(user.username);
        
        return res.json({
            success: true,
            user: {
                username: user.username,
                role: user.role,
                limits: user.limits || { server1: 0, server2: 0 },
                used: user.used || { server1: 0, server2: 0 }
            },
            broadcasts: broadcasts,
            limitStatus: limitStatus,
            serverStatus: DB.settings
        });
    } catch (error) {
        console.error('Get user error:', error);
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// LOGOUT
app.post('/api/logout', (req, res) => {
    try {
        req.session.destroy();
        return res.json({ success: true });
    } catch (error) {
        return res.json({ success: false });
    }
});

// ============ REDEEM ROUTES ============

// REDEEM CODE
app.post('/api/redeem', (req, res) => {
    try {
        if (!req.session || !req.session.user) {
            return res.json({ success: false, message: 'Silakan login terlebih dahulu' });
        }
        
        const { code, server } = req.body;
        const username = req.session.user.username;
        
        if (!code) {
            return res.json({ success: false, message: 'Masukkan kode redeem!' });
        }
        
        const redeemIndex = DB.redeemCodes.findIndex(r => r.code === code && !r.used);
        if (redeemIndex === -1) {
            return res.json({ success: false, message: 'Kode tidak valid atau sudah digunakan!' });
        }
        
        const redeem = DB.redeemCodes[redeemIndex];
        const user = findUser(username);
        if (!user) {
            return res.json({ success: false, message: 'User tidak ditemukan' });
        }
        
        // Tambah limit
        if (!user.limits) user.limits = { server1: 0, server2: 0 };
        user.limits[server] = (user.limits[server] || 0) + redeem.limit;
        
        // Tandai kode sudah digunakan
        redeem.used = true;
        redeem.usedBy = username;
        redeem.usedAt = new Date().toISOString();
        
        return res.json({ 
            success: true, 
            message: `Berhasil! +${redeem.limit} limit ditambahkan ke ${server === 'server1' ? 'Server 1' : 'Server 2'}`
        });
    } catch (error) {
        console.error('Redeem error:', error);
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// CREATE REDEEM CODE (OWNER)
app.post('/api/owner/create-redeem', (req, res) => {
    try {
        if (!req.session || !req.session.user || req.session.user.role !== 'owner') {
            return res.json({ success: false, message: 'Unauthorized' });
        }
        
        const { amount } = req.body;
        if (!amount || amount <= 0) {
            return res.json({ success: false, message: 'Jumlah limit tidak valid' });
        }
        
        let code;
        do {
            code = 'AMR-' + Math.random().toString(36).slice(2, 8).toUpperCase();
        } while (DB.redeemCodes.some(r => r.code === code));
        
        DB.redeemCodes.push({
            code: code,
            limit: amount,
            used: false,
            usedBy: null,
            usedAt: null,
            createdAt: new Date().toISOString()
        });
        
        return res.json({ success: true, code: code });
    } catch (error) {
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// GET REDEEM CODES (OWNER)
app.get('/api/owner/redeem-codes', (req, res) => {
    try {
        if (!req.session || !req.session.user || req.session.user.role !== 'owner') {
            return res.json({ success: false, message: 'Unauthorized' });
        }
        
        return res.json({ 
            success: true, 
            codes: DB.redeemCodes 
        });
    } catch (error) {
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// ============ OWNER ROUTES ============

// GET ALL USERS
app.get('/api/owner/users', (req, res) => {
    try {
        if (!req.session || !req.session.user || req.session.user.role !== 'owner') {
            return res.json({ success: false, message: 'Unauthorized' });
        }
        
        const users = DB.users.map(u => ({
            username: u.username,
            role: u.role,
            limits: u.limits || { server1: 0, server2: 0 },
            used: u.used || { server1: 0, server2: 0 }
        }));
        
        const bannedList = Object.keys(DB.bannedIPs).map(ip => ({
            ip: ip,
            bannedUntil: DB.bannedIPs[ip].bannedUntil,
            reason: DB.bannedIPs[ip].reason
        }));
        
        return res.json({ 
            success: true, 
            users, 
            serverStatus: DB.settings,
            bannedIPs: bannedList
        });
    } catch (error) {
        console.error('Get users error:', error);
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// UNBAN IP
app.post('/api/owner/unban-ip', (req, res) => {
    try {
        if (!req.session || !req.session.user || req.session.user.role !== 'owner') {
            return res.json({ success: false, message: 'Unauthorized' });
        }
        
        const { ip } = req.body;
        if (DB.bannedIPs[ip]) {
            delete DB.bannedIPs[ip];
            delete DB.ipTracker[ip];
            return res.json({ success: true, message: '✅ IP berhasil di-unban' });
        }
        return res.json({ success: false, message: 'IP tidak ditemukan' });
    } catch (error) {
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// TOGGLE SERVER
app.post('/api/owner/toggle-server', (req, res) => {
    try {
        if (!req.session || !req.session.user || req.session.user.role !== 'owner') {
            return res.json({ success: false, message: 'Unauthorized' });
        }
        
        const { server } = req.body;
        if (server === 'server1' || server === 'server2') {
            DB.settings[server] = !DB.settings[server];
            return res.json({ 
                success: true, 
                message: `✅ ${server} ${DB.settings[server] ? 'diaktifkan' : 'dinonaktifkan'}`,
                status: DB.settings[server]
            });
        } else {
            return res.json({ success: false, message: 'Server tidak dikenal' });
        }
    } catch (error) {
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// SEND BROADCAST
app.post('/api/owner/broadcast', (req, res) => {
    try {
        if (!req.session || !req.session.user || req.session.user.role !== 'owner') {
            return res.json({ success: false, message: 'Unauthorized' });
        }
        
        const { message } = req.body;
        if (!message) return res.json({ success: false, message: 'Pesan tidak boleh kosong' });
        
        const broadcast = {
            id: Date.now().toString(),
            message: message,
            createdAt: new Date().toISOString(),
            readBy: []
        };
        
        DB.broadcasts.push(broadcast);
        return res.json({ success: true, message: '✅ Broadcast terkirim!' });
    } catch (error) {
        return res.json({ success: false, message: '❌ Terjadi kesalahan' });
    }
});

// ============ MAGIC LINK ROUTES ============

// SEND MAGIC LINK
app.post('/api/send', async (req, res) => {
    try {
        if (!req.session || !req.session.user) {
            return res.json({ success: false, message: 'Silakan login terlebih dahulu' });
        }
        
        const { server, email } = req.body;
        const username = req.session.user.username;
        
        if (!email || !email.includes('@')) {
            return res.json({ success: false, message: 'Email tidak valid!' });
        }
        
        if (!DB.settings[server]) {
            return res.json({ 
                success: false, 
                message: `⚠️ ${server} sedang dimatikan oleh Owner.`
            });
        }
        
        const limitCheck = checkLimit(username, server);
        if (!limitCheck.allowed) {
            return res.json({ 
                success: false, 
                message: limitCheck.message,
                limitReached: true
            });
        }
        
        let result;
        if (server === 'server1') {
            result = await server1Send(email);
        } else if (server === 'server2') {
            result = await server2Send(email);
        } else {
            return res.json({ success: false, message: 'Server tidak dikenal' });
        }
        
        if (result.status === 'success' || result.ok || result.message?.includes('berhasil')) {
            useLimit(username, server);
            req.session.temp = { email, server };
            return res.json({ 
                success: true, 
                message: '✅ Magic link berhasil dikirim! Silakan cek email Anda.',
                detail: '📨 Link verifikasi telah dikirim ke email target. Cek inbox atau folder SPAM.'
            });
        } else {
            resetLimit(username, server);
            return res.json({ 
                success: false, 
                message: result.message || '❌ Gagal mengirim magic link',
                limitReset: true
            });
        }
    } catch (error) {
        console.error('Send error:', error);
        return res.json({ 
            success: false, 
            message: `❌ Error: ${error.message}`,
            limitReset: true
        });
    }
});

// VERIFY MAGIC LINK
app.post('/api/verify', async (req, res) => {
    try {
        if (!req.session || !req.session.user) {
            return res.json({ success: false, message: 'Silakan login terlebih dahulu' });
        }
        
        const { url } = req.body;
        const { email, server } = req.session.temp || {};
        
        if (!email || !server) {
            return res.json({ success: false, message: '⏳ Session expired, kirim ulang magic link' });
        }
        
        if (!DB.settings[server]) {
            return res.json({ 
                success: false, 
                message: `⚠️ ${server} sedang dimatikan oleh Owner.`
            });
        }
        
        let result;
        if (server === 'server1') {
            result = await server1Verify(email, url);
        } else if (server === 'server2') {
            result = await server2Verify(email, url);
        } else {
            return res.json({ success: false, message: 'Server tidak dikenal' });
        }
        
        if (result.status === 'success' || result.ok || result.message?.includes('berhasil')) {
            return res.json({ 
                success: true, 
                message: '🎉 Verifikasi berhasil!',
                detail: '✅ Akun Alight Motion berhasil diaktifkan! Nikmati fitur premium.'
            });
        } else {
            resetLimit(req.session.user.username, server);
            return res.json({ 
                success: false, 
                message: result.message || '❌ Verifikasi gagal',
                limitReset: true
            });
        }
    } catch (error) {
        console.error('Verify error:', error);
        return res.json({ 
            success: false, 
            message: `❌ Error: ${error.message}`,
            limitReset: true
        });
    }
});

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============ START SERVER ============
app.listen(PORT, () => {
    console.log('═══════════════════════════════════════════');
    console.log('  ⚡ XKelzz AM Generator v3.0');
    console.log('  Alight Motion Magic Link Tools');
    console.log('═══════════════════════════════════════════');
    console.log(`  🚀 Server running at http://localhost:${PORT}`);
    console.log(`  👑 Owner Login: KELL / 9089`);
    console.log(`  📡 ${CONFIG.server1.name}`);
    console.log(`  📡 ${CONFIG.server2.name}`);
    console.log('  🛡️ Anti-Spam: Aktif');
    console.log('  🎫 Redeem Code: Aktif');
    console.log('═══════════════════════════════════════════');
});