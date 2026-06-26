// ==================== LPA AUDIT BACKEND SERVER ====================
// Security: Token di .env, tidak terexpose ke client

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Octokit } = require('@octokit/rest');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== VALIDASI TOKEN ====================
if (!process.env.GITHUB_TOKEN) {
    console.error('❌ ERROR: GITHUB_TOKEN tidak ditemukan di .env');
    console.error('Silakan buat file .env dengan:');
    console.error('GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx');
    process.exit(1);
}

// ==================== KONFIGURASI GITHUB ====================
const GITHUB_CONFIG = {
    token: process.env.GITHUB_TOKEN,
    owner: process.env.GITHUB_OWNER || 'yusrinalzi',
    repo: process.env.GITHUB_REPO || 'LPA-AUDIT-APPS',
    branch: process.env.GITHUB_BRANCH || 'main'
};

console.log('========================================');
console.log('🔐 GitHub Configuration:');
console.log(`   Owner: ${GITHUB_CONFIG.owner}`);
console.log(`   Repo: ${GITHUB_CONFIG.repo}`);
console.log(`   Branch: ${GITHUB_CONFIG.branch}`);
console.log(`   Token: ${GITHUB_CONFIG.token ? '✅ SET' : '❌ NOT SET'}`);
console.log('========================================');

// ==================== MIDDLEWARE KEAMANAN ====================

// 1. Helmet - Security headers
app.use(helmet());

// 2. CORS - Batasi origin yang diizinkan
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:8080').split(',');
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
    credentials: true,
    maxAge: 86400 // 24 hours
}));

// 3. Rate Limiting - Cegah spam/brute force
const limiter = rateLimit({
    windowMs: (process.env.RATE_LIMIT_WINDOW || 15) * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX) || 10, // limit each IP to 10 requests per windowMs
    message: {
        success: false,
        error: 'Too many upload requests, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/upload', limiter);

// 4. Body parser dengan limit
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Logging (tanpa expose token)
app.use((req, res, next) => {
    console.log(`📝 ${req.method} ${req.path} - ${req.ip}`);
    next();
});

// ==================== INISIALISASI GITHUB ====================
const octokit = new Octokit({
    auth: GITHUB_CONFIG.token
});

// Test koneksi ke GitHub
async function testGitHubConnection() {
    try {
        await octokit.request('GET /repos/{owner}/{repo}', {
            owner: GITHUB_CONFIG.owner,
            repo: GITHUB_CONFIG.repo
        });
        console.log('✅ GitHub connection successful');
        return true;
    } catch (error) {
        console.error('❌ GitHub connection failed:', error.message);
        return false;
    }
}
testGitHubConnection();

// ==================== ENDPOINTS ====================

// 1. Health Check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        config: {
            owner: GITHUB_CONFIG.owner,
            repo: GITHUB_CONFIG.repo,
            branch: GITHUB_CONFIG.branch
        }
    });
});

// 2. Upload Image
app.post('/api/upload', async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { image, filename, folder = 'Images' } = req.body;
        
        // Validasi input
        if (!image) {
            return res.status(400).json({
                success: false,
                error: 'Image data is required'
            });
        }
        
        if (!filename) {
            return res.status(400).json({
                success: false,
                error: 'Filename is required'
            });
        }
        
        // Validasi ekstensi file
        const validExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'];
        const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
        if (!validExtensions.includes(ext)) {
            return res.status(400).json({
                success: false,
                error: `Invalid file type. Allowed: ${validExtensions.join(', ')}`
            });
        }
        
        // Validasi ukuran (max 5MB)
        const sizeInBytes = Buffer.from(image, 'base64').length;
        const maxSize = parseInt(process.env.MAX_FILE_SIZE) || 5242880;
        if (sizeInBytes > maxSize) {
            return res.status(400).json({
                success: false,
                error: `File too large. Max size: ${maxSize / 1024 / 1024}MB`
            });
        }
        
        console.log(`📤 Uploading: ${filename} (${(sizeInBytes / 1024).toFixed(2)}KB)`);
        
        // Generate unique filename
        const timestamp = Date.now();
        const cleanName = filename.replace(/[^a-zA-Z0-9.]/g, '_');
        const path = `${folder}/${timestamp}_${cleanName}`;
        
        // Upload ke GitHub
        const response = await octokit.request('PUT /repos/{owner}/{repo}/contents/{path}', {
            owner: GITHUB_CONFIG.owner,
            repo: GITHUB_CONFIG.repo,
            path: path,
            message: `Upload image: ${filename}`,
            content: image,
            branch: GITHUB_CONFIG.branch
        });
        
        // Generate raw URL
        const rawUrl = `https://raw.githubusercontent.com/${GITHUB_CONFIG.owner}/${GITHUB_CONFIG.repo}/${GITHUB_CONFIG.branch}/${path}`;
        
        const duration = Date.now() - startTime;
        console.log(`✅ Upload success: ${filename} (${duration}ms)`);
        console.log(`   URL: ${rawUrl}`);
        
        res.json({
            success: true,
            url: rawUrl,
            path: path,
            sha: response.data.content.sha,
            duration: duration
        });
        
    } catch (error) {
        console.error('❌ Upload error:', error.message);
        
        // Handle specific GitHub errors
        if (error.status === 401) {
            return res.status(401).json({
                success: false,
                error: 'GitHub authentication failed. Please check your token.'
            });
        }
        
        if (error.status === 404) {
            return res.status(404).json({
                success: false,
                error: 'Repository or path not found. Please check your configuration.'
            });
        }
        
        if (error.status === 422) {
            return res.status(422).json({
                success: false,
                error: 'File already exists or invalid path.'
            });
        }
        
        res.status(500).json({
            success: false,
            error: error.message || 'Internal server error'
        });
    }
});

// 3. Get repository info (tidak expose token)
app.get('/api/repo-info', async (req, res) => {
    try {
        const response = await octokit.request('GET /repos/{owner}/{repo}', {
            owner: GITHUB_CONFIG.owner,
            repo: GITHUB_CONFIG.repo
        });
        
        res.json({
            success: true,
            data: {
                name: response.data.name,
                description: response.data.description,
                private: response.data.private,
                default_branch: response.data.default_branch,
                size: response.data.size,
                stars: response.data.stargazers_count,
                forks: response.data.forks_count,
                open_issues: response.data.open_issues_count
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

// ==================== START SERVER ====================
app.listen(PORT, () => {
    console.log('========================================');
    console.log('🚀 LPA Audit Backend Server');
    console.log('========================================');
    console.log(`📡 Server running on: http://localhost:${PORT}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
    console.log(`📤 Upload endpoint: http://localhost:${PORT}/api/upload`);
    console.log(`📁 Repo info: http://localhost:${PORT}/api/repo-info`);
    console.log('========================================');
    console.log(`🔐 Security:`);
    console.log(`   ✅ Token di .env (tidak terexpose)`);
    console.log(`   ✅ Rate limiting: ${process.env.RATE_LIMIT_MAX || 10} requests per ${process.env.RATE_LIMIT_WINDOW || 15} minutes`);
    console.log(`   ✅ CORS: ${allowedOrigins.join(', ')}`);
    console.log(`   ✅ File size limit: ${(parseInt(process.env.MAX_FILE_SIZE) || 5242880) / 1024 / 1024}MB`);
    console.log('========================================');
});
