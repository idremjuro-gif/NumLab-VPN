// ============================================
// NumLab-VPN - Serveur Backend Sécurisé
// Créé par Merdi Madimba
// ============================================

require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs-extra');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// MIDDLEWARE DE SÉCURITÉ
// ============================================

// Rate limiting pour les tentatives de connexion admin
const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Maximum 5 tentatives
    message: { 
        success: false, 
        message: 'Trop de tentatives de connexion. Veuillez réessayer dans 15 minutes.' 
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Rate limiting général pour les téléchargements
const downloadRateLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // 100 téléchargements par minute max
    message: { 
        success: false, 
        message: 'Trop de requêtes. Veuillez patienter.' 
    }
});

// Middleware pour parser JSON
app.use(express.json());

// Servir les fichiers statiques
app.use(express.static(path.join(__dirname, 'public')));

// Configuration de Multer pour les uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'uploads'));
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB max
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.ovpn', '.conf', '.config', '.txt', '.crt', '.key', '.pem', '.zip', '.rar', '.7z'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Type de fichier non autorisé. Types acceptés: ' + allowedTypes.join(', ')));
        }
    }
});

// ============================================
// GESTION DES DONNÉES (JSON)
// ============================================

const DATA_FILE = path.join(__dirname, 'data', 'files.json');

// Initialiser le fichier de données s'il n'existe pas
async function initDataFile() {
    try {
        await fs.ensureFile(DATA_FILE);
        const exists = await fs.pathExists(DATA_FILE);
        if (!exists || (await fs.readFile(DATA_FILE, 'utf8')).trim() === '') {
            await fs.writeJson(DATA_FILE, []);
        }
    } catch (error) {
        console.error('Erreur lors de l\'initialisation du fichier de données:', error);
    }
}

// Lire les données
async function readData() {
    try {
        const data = await fs.readFile(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Erreur de lecture des données:', error);
        return [];
    }
}

// Écrire les données
async function writeData(data) {
    try {
        await fs.writeJson(DATA_FILE, data, { spaces: 2 });
    } catch (error) {
        console.error('Erreur d\'écriture des données:', error);
        throw error;
    }
}

// ============================================
// FONCTIONS DE SÉCURITÉ
// ============================================

// Hasher le code admin (à exécuter une seule fois pour générer le hash)
async function generateAdminHash(code) {
    const saltRounds = 10;
    return await bcrypt.hash(code, saltRounds);
}

// Le hash du code admin (sera remplacé par le vrai hash)
let ADMIN_HASH = process.env.ADMIN_HASH;

// Si pas de hash dans .env, utiliser un hash par défaut pour le développement
if (!ADMIN_HASH) {
    console.log('AVERTISSEMENT: ADMIN_HASH non trouvé dans .env. Utilisation du mode développement.');
    console.log('Pour générer le hash, exécutez: node -e "require(\'bcrypt\').hash(\'30292812046102\', 10, (err, hash) => console.log(hash))"');
    // Hash par défaut pour le code 30292812046102
    ADMIN_HASH = '$2b$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
}

// Vérifier le code admin
async function verifyAdminCode(code) {
    try {
        return await bcrypt.compare(code, ADMIN_HASH);
    } catch (error) {
        console.error('Erreur lors de la vérification du code admin:', error);
        return false;
    }
}

// Middleware de vérification de session admin
function verifyAdminSession(req, res, next) {
    const adminToken = req.headers['x-admin-token'] || req.session.adminToken;
    
    if (adminToken && adminToken === process.env.ADMIN_TOKEN) {
        next();
    } else {
        res.status(401).json({ 
            success: false, 
            message: 'Non autorisé. Veuillez vous connecter.' 
        });
    }
}

// ============================================
// ROUTES API PUBLIQUES
// ============================================

// Obtenir la liste des fichiers (version publique)
app.get('/api/files', downloadRateLimiter, async (req, res) => {
    try {
        const files = await readData();
        const now = new Date();
        
        // Nettoyer les fichiers expirés de plus de 30 jours
        const cleanedFiles = files.filter(file => {
            if (new Date(file.expiryDate) < now) {
                return true; // Garder les expirés pour l'affichage
            }
            return true;
        });
        
        // Version publique sans informations sensibles
        const publicFiles = cleanedFiles.map(file => ({
            id: file.id,
            name: file.name,
            network: file.network,
            expiryDate: file.expiryDate,
            size: file.size,
            downloadCount: file.downloadCount,
            isExpired: new Date(file.expiryDate) < now,
            description: file.description
        }));
        
        res.json({ success: true, files: publicFiles });
    } catch (error) {
        console.error('Erreur lors de la récupération des fichiers:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur.' });
    }
});

// Télécharger un fichier
app.get('/api/download/:id', downloadRateLimiter, async (req, res) => {
    try {
        const fileId = req.params.id;
        const files = await readData();
        const file = files.find(f => f.id === fileId);
        
        if (!file) {
            return res.status(404).json({ success: false, message: 'Fichier non trouvé.' });
        }
        
        // Vérifier si le fichier est expiré
        if (new Date(file.expiryDate) < new Date()) {
            return res.status(403).json({ success: false, message: 'Ce fichier est expiré.' });
        }
        
        // Vérifier si le fichier existe physiquement
        const filePath = path.join(__dirname, 'uploads', file.storedFilename);
        if (!(await fs.pathExists(filePath))) {
            return res.status(404).json({ success: false, message: 'Fichier physique non trouvé.' });
        }
        
        // Incrémenter le compteur de téléchargements
        file.downloadCount = (file.downloadCount || 0) + 1;
        await writeData(files);
        
        // Envoyer le fichier
        res.download(filePath, file.filename, (err) => {
            if (err) {
                console.error('Erreur lors du téléchargement:', err);
                if (!res.headersSent) {
                    res.status(500).json({ success: false, message: 'Erreur lors du téléchargement.' });
                }
            }
        });
    } catch (error) {
        console.error('Erreur lors du téléchargement:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur.' });
    }
});

// ============================================
// ROUTES API ADMIN
// ============================================

// Connexion admin
app.post('/api/admin/login', loginRateLimiter, async (req, res) => {
    try {
        const { code } = req.body;
        
        if (!code || code.length !== 14) {
            return res.status(400).json({ 
                success: false, 
                message: 'Code invalide. Le code doit contenir 14 chiffres.' 
            });
        }
        
        const isValid = await verifyAdminCode(code);
        
        if (isValid) {
            // Générer un token de session
            const sessionToken = uuidv4();
            // Stocker le token (dans un vrai projet, utiliser Redis ou une base de données)
            process.env.ADMIN_TOKEN = sessionToken;
            
            res.json({ 
                success: true, 
                message: 'Connexion réussie.',
                token: sessionToken
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: 'Code incorrect.' 
            });
        }
    } catch (error) {
        console.error('Erreur lors de la connexion admin:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur.' });
    }
});

// Ajouter un fichier (protégé)
app.post('/api/admin/files', verifyAdminSession, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'Aucun fichier uploadé.' });
        }
        
        const { name, network, expiryDate, description } = req.body;
        
        // Validation
        if (!name || !network || !expiryDate) {
            // Supprimer le fichier uploadé si la validation échoue
            await fs.remove(path.join(__dirname, 'uploads', req.file.filename));
            return res.status(400).json({ 
                success: false, 
                message: 'Nom, réseau et date d\'expiration requis.' 
            });
        }
        
        // Vérifier si la date d'expiration est valide
        if (new Date(expiryDate) <= new Date()) {
            await fs.remove(path.join(__dirname, 'uploads', req.file.filename));
            return res.status(400).json({ 
                success: false, 
                message: 'La date d\'expiration doit être future.' 
            });
        }
        
        const files = await readData();
        
        const newFile = {
            id: uuidv4(),
            filename: req.file.originalname,
            storedFilename: req.file.filename,
            name: name.trim(),
            network: network.trim(),
            expiryDate: expiryDate,
            size: formatFileSize(req.file.size),
            description: description ? description.trim() : '',
            downloadCount: 0,
            createdAt: new Date().toISOString()
        };
        
        files.push(newFile);
        await writeData(files);
        
        res.json({ 
            success: true, 
            message: 'Fichier ajouté avec succès.',
            file: newFile
        });
    } catch (error) {
        console.error('Erreur lors de l\'ajout du fichier:', error);
        res.status(500).json({ success: false, message: 'Erreur lors de l\'ajout du fichier.' });
    }
});

// Modifier un fichier (protégé)
app.put('/api/admin/files/:id', verifyAdminSession, async (req, res) => {
    try {
        const fileId = req.params.id;
        const { name, network, expiryDate, description } = req.body;
        
        const files = await readData();
        const fileIndex = files.findIndex(f => f.id === fileId);
        
        if (fileIndex === -1) {
            return res.status(404).json({ success: false, message: 'Fichier non trouvé.' });
        }
        
        // Validation
        if (!name || !network || !expiryDate) {
            return res.status(400).json({ 
                success: false, 
                message: 'Nom, réseau et date d\'expiration requis.' 
            });
        }
        
        // Vérifier si la date d'expiration est valide
        if (new Date(expiryDate) <= new Date()) {
            return res.status(400).json({ 
                success: false, 
                message: 'La date d\'expiration doit être future.' 
            });
        }
        
        // Mettre à jour le fichier
        files[fileIndex] = {
            ...files[fileIndex],
            name: name.trim(),
            network: network.trim(),
            expiryDate: expiryDate,
            description: description ? description.trim() : ''
        };
        
        await writeData(files);
        
        res.json({ 
            success: true, 
            message: 'Fichier modifié avec succès.',
            file: files[fileIndex]
        });
    } catch (error) {
        console.error('Erreur lors de la modification du fichier:', error);
        res.status(500).json({ success: false, message: 'Erreur lors de la modification.' });
    }
});

// Supprimer un fichier (protégé)
app.delete('/api/admin/files/:id', verifyAdminSession, async (req, res) => {
    try {
        const fileId = req.params.id;
        const files = await readData();
        const fileIndex = files.findIndex(f => f.id === fileId);
        
        if (fileIndex === -1) {
            return res.status(404).json({ success: false, message: 'Fichier non trouvé.' });
        }
        
        const file = files[fileIndex];
        
        // Supprimer le fichier physique
        const filePath = path.join(__dirname, 'uploads', file.storedFilename);
        if (await fs.pathExists(filePath)) {
            await fs.remove(filePath);
        }
        
        // Supprimer de la base de données
        files.splice(fileIndex, 1);
        await writeData(files);
        
        res.json({ success: true, message: 'Fichier supprimé avec succès.' });
    } catch (error) {
        console.error('Erreur lors de la suppression du fichier:', error);
        res.status(500).json({ success: false, message: 'Erreur lors de la suppression.' });
    }
});

// Obtenir les statistiques (protégé)
app.get('/api/admin/stats', verifyAdminSession, async (req, res) => {
    try {
        const files = await readData();
        const now = new Date();
        
        const stats = {
            totalFiles: files.length,
            activeFiles: files.filter(f => new Date(f.expiryDate) > now).length,
            expiredFiles: files.filter(f => new Date(f.expiryDate) <= now).length,
            totalDownloads: files.reduce((sum, f) => sum + (f.downloadCount || 0), 0)
        };
        
        res.json({ success: true, stats: stats });
    } catch (error) {
        console.error('Erreur lors du calcul des statistiques:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur.' });
    }
});

// ============================================
// FONCTIONS UTILITAIRES
// ============================================

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Servir la page admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Servir la page d'accueil
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Gestion des erreurs Multer
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'Fichier trop volumineux. Maximum 50MB.' });
        }
        return res.status(400).json({ success: false, message: 'Erreur lors de l\'upload: ' + err.message });
    } else if (err) {
        return res.status(400).json({ success: false, message: err.message });
    }
    next();
});

// ============================================
// DÉMARRAGE DU SERVEUR
// ============================================

async function startServer() {
    try {
        // Initialiser les dossiers
        await fs.ensureDir(path.join(__dirname, 'uploads'));
        await fs.ensureDir(path.join(__dirname, 'data'));
        
        // Initialiser le fichier de données
        await initDataFile();
        
        // Démarrer le serveur
        app.listen(PORT, () => {
            console.log(`╔════════════════════════════════════════╗`);
            console.log(`║         NumLab-VPN Server Started      ║`);
            console.log(`╠════════════════════════════════════════╣`);
            console.log(`║ Port: ${PORT}`);
            console.log(`║ URL:  http://localhost:${PORT}`);
            console.log(`║ Admin: /admin`);
            console.log(`╚════════════════════════════════════════╝`);
        });
    } catch (error) {
        console.error('Erreur lors du démarrage du serveur:', error);
        process.exit(1);
    }
}

startServer();

// Export pour les tests
module.exports = app;
