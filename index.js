require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult, param } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');

const app = express();

// ========== LOGS ==========
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({ format: winston.format.combine(winston.format.colorize(), winston.format.simple()) })
    ]
});

// ========== SEGURIDAD ==========
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const allowedOrigins = [
    'https://roucedevstudio.github.io',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) callback(null, true);
        else callback(new Error('CORS no permitido'));
    },
    credentials: true
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ========== RATE LIMITING ==========
const generalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { error: "Demasiadas peticiones" }, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: "Demasiados intentos" }, skipSuccessfulRequests: true });
const createLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 50, message: { error: "Límite de creación alcanzado" } });

app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/items/add', createLimiter);
app.use(generalLimiter);

// ========== LOG DE REQUESTS ==========
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const logData = { method: req.method, path: req.path, status: res.statusCode, duration: `${duration}ms`, ip: req.ip };
        res.statusCode >= 400 ? logger.error('Request error', logData) : logger.info('Request', logData);
    });
    next();
});

// ========== MONGODB ==========
const connectDB = async () => {
    const maxRetries = 5;
    let retries = 0;
    while (retries < maxRetries) {
        try {
            await mongoose.connect(process.env.MONGODB_URI, { maxPoolSize: 10, serverSelectionTimeoutMS: 5000, socketTimeoutMS: 45000 });
            logger.info('🚀 MONGODB CONECTADO');
            return;
        } catch (err) {
            retries++;
            logger.error(`❌ MongoDB intento ${retries}/${maxRetries}:`, err.message);
            if (retries === maxRetries) { logger.error('❌ MONGODB FALLIDO'); process.exit(1); }
            await new Promise(r => setTimeout(r, 5000));
        }
    }
};
connectDB();
mongoose.connection.on('disconnected', () => logger.warn('⚠️ MongoDB desconectado'));
mongoose.connection.on('error', (err) => logger.error('❌ MongoDB error:', err));

// ========== SCHEMAS ==========

// --- Juego ---
const JuegoSchema = new mongoose.Schema({
    usuario: { type: String, required: true, index: true, trim: true },
    title: { type: String, required: true, maxlength: 200, trim: true, index: true },
    description: { type: String, maxlength: 1000, default: '' },
    image: { type: String, validate: { validator: v => !v || /^https?:\/\/.+/.test(v), message: 'URL imagen inválida' } },
    link: { type: String, required: true, validate: { validator: v => /^https?:\/\/.+/.test(v), message: 'URL inválida' } },
    status: { type: String, enum: ["pendiente", "aprobado", "rechazado"], default: "pendiente", index: true },
    reportes: { type: Number, default: 0, min: 0 },
    category: { type: String, default: "General", trim: true },
    tags: [{ type: String, maxlength: 30, trim: true }],
    vistas: { type: Number, default: 0 },
    likes: { type: Number, default: 0 }
}, { timestamps: true });

JuegoSchema.index({ usuario: 1, status: 1 });
JuegoSchema.index({ category: 1, status: 1 });
JuegoSchema.index({ createdAt: -1 });
JuegoSchema.index({ title: 'text', description: 'text' });
const Juego = mongoose.model('Juego', JuegoSchema);

// --- Usuario ---
const UsuarioSchema = new mongoose.Schema({
    usuario: {
        type: String, required: true, unique: true, index: true,
        minlength: 3, maxlength: 20, trim: true, lowercase: true,
        validate: { validator: v => /^[a-z0-9_]+$/.test(v), message: 'Solo letras, números y _' }
    },
    password: { type: String, required: true, minlength: 6, select: false },
    listaSeguidores: [{ type: String }],
    siguiendo: [{ type: String }],
    verificadoNivel: { type: Number, default: 0, min: 0, max: 3, index: true },
    avatar: { type: String, default: '', validate: { validator: v => !v || /^https?:\/\/.+/.test(v), message: 'URL avatar inválida' } },
    bio: { type: String, maxlength: 200, default: '' },
    rol: { type: String, enum: ["usuario", "moderador", "admin"], default: "usuario", index: true },
    bloqueado: { type: Boolean, default: false, index: true },
    ultimoLogin: Date,
    intentosLoginFallidos: { type: Number, default: 0 },
    bloqueoHasta: Date
}, { timestamps: true });

UsuarioSchema.index({ rol: 1, bloqueado: 1 });

// PRE-SAVE: hash password
UsuarioSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try { this.password = await bcrypt.hash(this.password, 12); next(); }
    catch (e) { next(e); }
});

UsuarioSchema.methods.compararPassword = async function(pwd) { return bcrypt.compare(pwd, this.password); };

UsuarioSchema.methods.actualizarVerificacionAuto = async function() {
    const count = this.listaSeguidores ? this.listaSeguidores.length : 0;
    let nuevoNivel = 0;
    if (count >= 1000) nuevoNivel = 3;
    else if (count >= 100) nuevoNivel = 2;
    else if (count >= 50) nuevoNivel = 1;
    if (nuevoNivel > this.verificadoNivel) {
        this.verificadoNivel = nuevoNivel;
        await this.save();
        logger.info(`Usuario ${this.usuario} subió a verificación nivel ${nuevoNivel}`);
    }
};

UsuarioSchema.methods.generarToken = function() {
    return jwt.sign({ id: this._id, usuario: this.usuario, rol: this.rol }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
};

UsuarioSchema.methods.generarRefreshToken = function() {
    return jwt.sign({ id: this._id }, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d' });
};

const Usuario = mongoose.model("Usuario", UsuarioSchema);

// --- Comentario ---
const ComentarioSchema = new mongoose.Schema({
    usuario: { type: String, required: true, trim: true, index: true },
    texto: { type: String, required: true, maxlength: 500, trim: true },
    itemId: { type: String, required: true, index: true },
    editado: { type: Boolean, default: false },
    likes: { type: Number, default: 0 }
}, { timestamps: true });
ComentarioSchema.index({ itemId: 1, createdAt: -1 });
const Comentario = mongoose.model('Comentario', ComentarioSchema);

// --- Favorito ---
const FavoritoSchema = new mongoose.Schema({
    usuario: { type: String, required: true, index: true, trim: true },
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego', required: true, index: true }
}, { timestamps: true });
FavoritoSchema.index({ usuario: 1, itemId: 1 }, { unique: true });
const Favorito = mongoose.model('Favorito', FavoritoSchema);

// --- Refresh Token ---
const RefreshTokenSchema = new mongoose.Schema({
    token: { type: String, required: true, unique: true },
    usuarioId: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario', required: true },
    expiresAt: { type: Date, required: true }
}, { timestamps: true });
RefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);

// ========== MIDDLEWARES DE AUTENTICACIÓN ==========

const verificarToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: "Token requerido", codigo: "NO_TOKEN" });
        }
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const usuario = await Usuario.findById(decoded.id).select('-password').lean();
            if (!usuario) return res.status(401).json({ error: "Usuario no encontrado", codigo: "USER_NOT_FOUND" });
            if (usuario.bloqueado) return res.status(403).json({ error: "Usuario bloqueado", codigo: "USER_BLOCKED" });
            req.usuario = usuario.usuario;
            req.usuarioId = usuario._id;
            req.rol = usuario.rol;
            req.usuarioCompleto = usuario;
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') return res.status(401).json({ error: "Token expirado", codigo: "TOKEN_EXPIRED" });
            return res.status(401).json({ error: "Token inválido", codigo: "INVALID_TOKEN" });
        }
    } catch (error) {
        logger.error('Error en verificarToken:', error);
        res.status(500).json({ error: "Error de autenticación" });
    }
};

const verificarAdmin = (req, res, next) => {
    if (req.rol !== "admin" && req.rol !== "moderador") return res.status(403).json({ error: "Acceso denegado", codigo: "FORBIDDEN" });
    next();
};

const verificarSoloAdmin = (req, res, next) => {
    if (req.rol !== "admin") return res.status(403).json({ error: "Solo administradores", codigo: "ADMIN_ONLY" });
    next();
};

const verificarTokenOpcional = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) return next();
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const usuario = await Usuario.findById(decoded.id).select('-password').lean();
            if (usuario && !usuario.bloqueado) {
                req.usuario = usuario.usuario;
                req.usuarioId = usuario._id;
                req.rol = usuario.rol;
            }
        } catch (e) { /* token inválido, continuar sin auth */ }
        next();
    } catch (error) { next(); }
};

// ========== RUTAS DE AUTENTICACIÓN ==========

// REGISTRO
app.post("/auth/register", [
    body('usuario').trim().toLowerCase().isLength({ min: 3, max: 20 }).matches(/^[a-z0-9_]+$/).withMessage('Usuario: 3-20 caracteres, solo letras, números y _'),
    body('password').isLength({ min: 6 }).withMessage('Password: mínimo 6 caracteres')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, errores: errors.array().map(e => e.msg) });

        const { usuario, password } = req.body;
        const existeUsuario = await Usuario.findOne({ usuario: usuario.toLowerCase() });
        if (existeUsuario) return res.status(400).json({ success: false, mensaje: "El usuario ya existe" });

        const nuevoUsuario = new Usuario({ usuario: usuario.toLowerCase(), password });
        await nuevoUsuario.save();

        const token = nuevoUsuario.generarToken();
        const refreshToken = nuevoUsuario.generarRefreshToken();
        await RefreshToken.create({ token: refreshToken, usuarioId: nuevoUsuario._id, expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) });

        logger.info(`✅ Nuevo usuario: ${usuario}`);

        res.status(201).json({
            success: true,
            mensaje: "Usuario creado exitosamente",
            token,
            refreshToken,
            usuario: {
                usuario: nuevoUsuario.usuario,
                verificadoNivel: nuevoUsuario.verificadoNivel,
                avatar: nuevoUsuario.avatar,
                rol: nuevoUsuario.rol
            }
        });
    } catch (error) {
        logger.error('❌ Error registro:', error);
        if (error.code === 11000) return res.status(400).json({ success: false, mensaje: "El usuario ya existe" });
        res.status(500).json({ success: false, mensaje: "Error del servidor" });
    }
});

// LOGIN
app.post("/auth/login", [
    body('usuario').trim().notEmpty().withMessage('Usuario requerido'),
    body('password').notEmpty().withMessage('Password requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "Datos incompletos" });

        const { usuario, password } = req.body;
        const user = await Usuario.findOne({ usuario: usuario.toLowerCase() }).select('+password');

        if (!user) return res.status(401).json({ success: false, mensaje: "Credenciales incorrectas", codigo: "INVALID_CREDENTIALS" });

        if (user.bloqueoHasta && user.bloqueoHasta > new Date()) {
            const min = Math.ceil((user.bloqueoHasta - new Date()) / 60000);
            return res.status(403).json({ success: false, mensaje: `Bloqueado por ${min} minutos`, codigo: "TEMP_BLOCKED" });
        }

        if (user.bloqueado) return res.status(403).json({ success: false, mensaje: "Usuario bloqueado permanentemente", codigo: "USER_BLOCKED" });

        const passwordValida = await user.compararPassword(password);
        if (!passwordValida) {
            user.intentosLoginFallidos += 1;
            if (user.intentosLoginFallidos >= 5) {
                user.bloqueoHasta = new Date(Date.now() + 15 * 60 * 1000);
                user.intentosLoginFallidos = 0;
                await user.save();
                return res.status(403).json({ success: false, mensaje: "Bloqueado por 15 minutos por intentos fallidos", codigo: "TOO_MANY_ATTEMPTS" });
            }
            await user.save();
            return res.status(401).json({ success: false, mensaje: "Credenciales incorrectas", intentosRestantes: 5 - user.intentosLoginFallidos, codigo: "INVALID_CREDENTIALS" });
        }

        user.intentosLoginFallidos = 0;
        user.bloqueoHasta = undefined;
        user.ultimoLogin = new Date();
        await user.save();

        const token = user.generarToken();
        const refreshToken = user.generarRefreshToken();
        await RefreshToken.create({ token: refreshToken, usuarioId: user._id, expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) });

        logger.info(`✅ Login: ${usuario}`);

        res.json({
            success: true,
            mensaje: "Login exitoso",
            token,
            refreshToken,
            usuario: {
                usuario: user.usuario,
                verificadoNivel: user.verificadoNivel,
                avatar: user.avatar,
                rol: user.rol,
                seguidores: user.listaSeguidores ? user.listaSeguidores.length : 0,
                bio: user.bio
            }
        });
    } catch (error) {
        logger.error('❌ Error login:', error);
        res.status(500).json({ success: false, mensaje: "Error del servidor" });
    }
});

// REFRESH TOKEN
app.post("/auth/refresh", [body('refreshToken').notEmpty()], async (req, res) => {
    try {
        const { refreshToken } = req.body;
        const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
        if (!tokenDoc) return res.status(401).json({ success: false, mensaje: "Refresh token inválido" });
        if (tokenDoc.expiresAt < new Date()) { await RefreshToken.deleteOne({ _id: tokenDoc._id }); return res.status(401).json({ success: false, mensaje: "Refresh token expirado" }); }
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const usuario = await Usuario.findById(decoded.id).select('-password');
        if (!usuario || usuario.bloqueado) return res.status(401).json({ success: false, mensaje: "Usuario no válido" });
        res.json({ success: true, token: usuario.generarToken() });
    } catch (error) {
        logger.error('❌ Error refresh:', error);
        res.status(401).json({ success: false, mensaje: "Refresh token inválido" });
    }
});

// LOGOUT
app.post("/auth/logout", verificarToken, async (req, res) => {
    try {
        if (req.body.refreshToken) await RefreshToken.deleteOne({ token: req.body.refreshToken });
        res.json({ success: true, mensaje: "Logout exitoso" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// VERIFY TOKEN
app.get("/auth/verify", verificarToken, (req, res) => res.json({ success: true, usuario: req.usuarioCompleto }));

// ========== RUTAS DE USUARIOS ==========

// Perfil propio
app.get("/auth/me", verificarToken, async (req, res) => {
    try {
        const usuario = await Usuario.findById(req.usuarioId).select('-password').lean();
        const cantidadItems = await Juego.countDocuments({ usuario: usuario.usuario, status: 'aprobado' });
        const cantidadFavoritos = await Favorito.countDocuments({ usuario: usuario.usuario });
        res.json({ success: true, usuario: { ...usuario, seguidores: usuario.listaSeguidores ? usuario.listaSeguidores.length : 0, cantidadSiguiendo: usuario.siguiendo ? usuario.siguiendo.length : 0, cantidadItems, cantidadFavoritos } });
    } catch (e) { logger.error('❌ Error perfil:', e); res.status(500).json({ success: false }); }
});

// Perfil público de otro usuario
app.get("/auth/perfil/:usuario", async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.params.usuario.toLowerCase() }).select('-password').lean();
        if (!usuario) return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        const cantidadItems = await Juego.countDocuments({ usuario: usuario.usuario, status: 'aprobado' });
        res.json({ success: true, usuario: { ...usuario, seguidores: usuario.listaSeguidores ? usuario.listaSeguidores.length : 0, cantidadSiguiendo: usuario.siguiendo ? usuario.siguiendo.length : 0, cantidadItems } });
    } catch (e) { logger.error('❌ Error perfil público:', e); res.status(500).json({ success: false }); }
});

// ========== RUTA PÚBLICA: LISTA DE USUARIOS (para mapear verificados en biblioteca) ==========
// ÚNICA definición. Sin autenticación. Devuelve solo campos públicos.
app.get("/auth/users-public", async (req, res) => {
    try {
        const usuarios = await Usuario.find({}).select('usuario verificadoNivel avatar bio').lean();
        // Agregar conteo de seguidores manualmente (no es virtual ni campo real directamente)
        const result = usuarios.map(u => ({
            ...u,
            seguidores: u.listaSeguidores ? u.listaSeguidores.length : 0
        }));
        res.json(result);
    } catch (e) {
        logger.error('❌ Error users-public:', e);
        res.status(500).json({ success: false, message: "Error del servidor" });
    }
});

// ========== RUTA ADMIN: LISTA DE USUARIOS (con autenticación y paginación) ==========
app.get("/auth/users", verificarToken, verificarAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, search, rol, bloqueado } = req.query;
        let query = {};
        if (search) query.usuario = { $regex: search, $options: 'i' };
        if (rol) query.rol = rol;
        if (bloqueado !== undefined) query.bloqueado = bloqueado === 'true';
        const skip = (page - 1) * limit;
        const [usuarios, total] = await Promise.all([
            Usuario.find(query).select('-password').sort({ createdAt: -1 }).limit(parseInt(limit)).skip(skip).lean(),
            Usuario.countDocuments(query)
        ]);
        // Agregar conteo de seguidores
        const result = usuarios.map(u => ({ ...u, seguidores: u.listaSeguidores ? u.listaSeguidores.length : 0 }));
        res.json({ success: true, usuarios: result, pagination: { total, page: parseInt(page), pages: Math.ceil(total / limit) } });
    } catch (e) { logger.error('❌ Error listando usuarios:', e); res.status(500).json({ success: false }); }
});

// Actualizar avatar
app.put("/auth/update-avatar", verificarToken, [body('nuevaFoto').isURL().withMessage('URL inválida')], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "URL inválida" });
        await Usuario.findOneAndUpdate({ usuario: req.usuario }, { avatar: req.body.nuevaFoto });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Actualizar bio
app.put("/auth/update-bio", verificarToken, [body('bio').trim().isLength({ max: 200 })], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "Bio muy larga" });
        await Usuario.findOneAndUpdate({ usuario: req.usuario }, { bio: req.body.bio });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ========== SEGUIR / DEJAR DE SEGUIR (ÚNICA definición cada una) ==========

// SEGUIR a un usuario
app.post("/usuarios/seguir", verificarToken, async (req, res) => {
    try {
        const { siguiendo } = req.body;
        const seguidor = req.usuario; // Siempre usar el usuario autenticado

        if (!siguiendo) return res.status(400).json({ success: false, message: "Falta el usuario a seguir" });

        const target = siguiendo.toLowerCase().trim();
        if (target === seguidor) return res.status(400).json({ success: false, message: "No puedes seguirte a ti mismo" });

        const [usuarioSeguidor, usuarioTarget] = await Promise.all([
            Usuario.findOne({ usuario: seguidor }),
            Usuario.findOne({ usuario: target })
        ]);

        if (!usuarioTarget) return res.status(404).json({ success: false, message: "El usuario que intentas seguir no existe" });
        if (!usuarioSeguidor) return res.status(404).json({ success: false, message: "Tu usuario no existe" });

        // Verificar si ya lo sigue
        if (usuarioTarget.listaSeguidores && usuarioTarget.listaSeguidores.includes(seguidor)) {
            return res.status(400).json({ success: false, message: "Ya sigues a este usuario" });
        }

        // Agregar
        if (!usuarioTarget.listaSeguidores) usuarioTarget.listaSeguidores = [];
        if (!usuarioSeguidor.siguiendo) usuarioSeguidor.siguiendo = [];

        usuarioTarget.listaSeguidores.push(seguidor);
        usuarioSeguidor.siguiendo.push(target);

        await Promise.all([usuarioTarget.save(), usuarioSeguidor.save()]);
        await usuarioTarget.actualizarVerificacionAuto();

        logger.info(`✅ ${seguidor} ahora sigue a ${target}`);

        res.status(201).json({
            success: true,
            message: `Ahora sigues a @${target}`,
            seguidores: usuarioTarget.listaSeguidores.length,
            verificadoNivel: usuarioTarget.verificadoNivel
        });
    } catch (error) {
        logger.error('❌ Error seguir:', error);
        res.status(500).json({ success: false, message: "Error del servidor" });
    }
});

// DEJAR DE SEGUIR a un usuario
app.delete("/usuarios/dejar-seguir", verificarToken, async (req, res) => {
    try {
        const { siguiendo } = req.body;
        const seguidor = req.usuario;

        if (!siguiendo) return res.status(400).json({ success: false, message: "Falta el usuario" });

        const target = siguiendo.toLowerCase().trim();

        const [usuarioSeguidor, usuarioTarget] = await Promise.all([
            Usuario.findOne({ usuario: seguidor }),
            Usuario.findOne({ usuario: target })
        ]);

        if (!usuarioTarget || !usuarioSeguidor) return res.status(404).json({ success: false, message: "Usuario no encontrado" });

        // Verificar que lo sigue
        if (!usuarioTarget.listaSeguidores || !usuarioTarget.listaSeguidores.includes(seguidor)) {
            return res.status(404).json({ success: false, message: "No seguías a este usuario" });
        }

        usuarioTarget.listaSeguidores = usuarioTarget.listaSeguidores.filter(s => s !== seguidor);
        usuarioSeguidor.siguiendo = usuarioSeguidor.siguiendo.filter(s => s !== target);

        await Promise.all([usuarioTarget.save(), usuarioSeguidor.save()]);

        logger.info(`✅ ${seguidor} dejó de seguir a ${target}`);

        res.json({ success: true, message: `Dejaste de seguir a @${target}`, seguidores: usuarioTarget.listaSeguidores.length });
    } catch (error) {
        logger.error('❌ Error dejar seguir:', error);
        res.status(500).json({ success: false, message: "Error del servidor" });
    }
});

// Obtener lista de usuarios que sigue alguien
app.get("/usuarios/siguiendo/:usuario", async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.params.usuario.toLowerCase().trim() }).select('siguiendo').lean();
        if (!usuario) return res.status(404).json({ success: false, message: "Usuario no encontrado" });
        res.json({ success: true, siguiendo: usuario.siguiendo || [] });
    } catch (e) {
        logger.error('❌ Error siguiendo:', e);
        res.status(500).json({ success: false, message: "Error del servidor" });
    }
});

// Obtener lista de seguidores de un usuario
app.get("/usuarios/seguidores/:usuario", async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.params.usuario.toLowerCase().trim() }).select('listaSeguidores').lean();
        if (!usuario) return res.status(404).json({ success: false, message: "Usuario no encontrado" });
        res.json({ success: true, seguidores: usuario.listaSeguidores || [] });
    } catch (e) {
        logger.error('❌ Error seguidores:', e);
        res.status(500).json({ success: false, message: "Error del servidor" });
    }
});

// Estadísticas de seguimiento
app.get("/usuarios/stats-seguimiento/:usuario", async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.params.usuario.toLowerCase().trim() }).select('listaSeguidores siguiendo').lean();
        if (!usuario) return res.status(404).json({ success: false, message: "Usuario no encontrado" });
        res.json({
            success: true,
            stats: {
                seguidores: usuario.listaSeguidores ? usuario.listaSeguidores.length : 0,
                siguiendo: usuario.siguiendo ? usuario.siguiendo.length : 0
            }
        });
    } catch (e) {
        logger.error('❌ Error stats:', e);
        res.status(500).json({ success: false, message: "Error del servidor" });
    }
});

// Actualizar perfil (avatar + bio) — ruta que usa el frontend
app.put("/usuarios/actualizar-perfil", verificarToken, async (req, res) => {
    try {
        const { avatar, bio } = req.body;
        const user = await Usuario.findOne({ usuario: req.usuario });
        if (!user) return res.status(404).json({ success: false, message: "Usuario no encontrado" });
        if (avatar !== undefined) user.avatar = avatar;
        if (bio !== undefined) user.bio = bio;
        await user.save();
        logger.info(`Usuario ${req.usuario} actualizó perfil`);
        res.json({ success: true, message: "Perfil actualizado", avatar: user.avatar, bio: user.bio });
    } catch (e) {
        logger.error('❌ Error actualizar perfil:', e);
        res.status(500).json({ success: false, message: "Error del servidor" });
    }
});

// Eliminar usuario (SOLO ADMIN)
app.delete("/auth/users/:id", verificarToken, verificarSoloAdmin, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const usuario = await Usuario.findById(req.params.id);
        if (!usuario) return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        if (usuario.rol === 'admin' && req.usuarioId.toString() !== req.params.id) return res.status(403).json({ success: false, mensaje: "No puedes eliminar otros admins" });
        await Usuario.findByIdAndDelete(req.params.id);
        logger.warn(`Admin ${req.usuario} eliminó usuario ${usuario.usuario}`);
        res.json({ success: true, mensaje: "Usuario eliminado" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Bloquear/Desbloquear usuario (ADMIN)
app.put("/auth/users/:id/bloquear", verificarToken, verificarAdmin, [param('id').isMongoId(), body('bloqueado').isBoolean()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "Datos inválidos" });
        const usuario = await Usuario.findById(req.params.id);
        if (!usuario) return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        if (usuario.rol === 'admin') return res.status(403).json({ success: false, mensaje: "No puedes bloquear admins" });
        usuario.bloqueado = req.body.bloqueado;
        await usuario.save();
        res.json({ success: true, mensaje: `Usuario ${req.body.bloqueado ? 'bloqueado' : 'desbloqueado'}` });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Cambiar verificación manual (ADMIN)
app.put("/auth/admin/verificacion/:usuario", verificarToken, verificarAdmin, [body('nivel').isInt({ min: 0, max: 3 })], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "Nivel inválido (0-3)" });
        const user = await Usuario.findOneAndUpdate({ usuario: req.params.usuario.toLowerCase() }, { verificadoNivel: req.body.nivel }, { new: true }).select('-password');
        if (!user) return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        logger.info(`Admin ${req.usuario} → verificación de ${user.usuario} = nivel ${req.body.nivel}`);
        res.json({ success: true, verificadoNivel: user.verificadoNivel });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Cambiar rol (SOLO ADMIN)
app.put("/auth/admin/rol/:id", verificarToken, verificarSoloAdmin, [param('id').isMongoId(), body('rol').isIn(['usuario', 'moderador', 'admin'])], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "Datos inválidos" });
        const usuario = await Usuario.findByIdAndUpdate(req.params.id, { rol: req.body.rol }, { new: true }).select('-password');
        if (!usuario) return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        res.json({ success: true, usuario });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ========== RUTAS DE ITEMS ==========

// Listar items (público, con filtros)
app.get("/items", verificarTokenOpcional, async (req, res) => {
    try {
        const { status = 'aprobado', usuario, category, search, limit = 50, page = 1, sortBy = 'createdAt', order = 'desc' } = req.query;
        let query = {};
        if (status) query.status = status;
        if (usuario) query.usuario = usuario.toLowerCase();
        if (category && category !== 'Todas') query.category = category;
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }
        const skip = (page - 1) * limit;
        const sortOrder = order === 'desc' ? -1 : 1;
        const [items, total] = await Promise.all([
            Juego.find(query).sort({ [sortBy]: sortOrder }).limit(parseInt(limit)).skip(skip).lean(),
            Juego.countDocuments(query)
        ]);
        res.json({ success: true, items, pagination: { total, page: parseInt(page), pages: Math.ceil(total / limit) } });
    } catch (e) { logger.error('❌ Error items:', e); res.status(500).json({ success: false, error: "Error interno" }); }
});

// Items de un usuario específico
app.get("/items/user/:usuario", async (req, res) => {
    try {
        const { page = 1, limit = 50, status } = req.query;
        let query = { usuario: req.params.usuario.toLowerCase() };
        if (status) query.status = status;
        const skip = (page - 1) * limit;
        const [items, total] = await Promise.all([
            Juego.find(query).sort({ createdAt: -1 }).limit(parseInt(limit)).skip(skip).lean(),
            Juego.countDocuments(query)
        ]);
        res.json({ success: true, items, pagination: { total, page: parseInt(page), pages: Math.ceil(total / limit) } });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Item específico por ID
app.get("/items/:id", verificarTokenOpcional, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const item = await Juego.findById(req.params.id).lean();
        if (!item) return res.status(404).json({ success: false, mensaje: "Item no encontrado" });
        await Juego.findByIdAndUpdate(req.params.id, { $inc: { vistas: 1 } });
        res.json({ success: true, item });
    } catch (e) { res.status(500).json({ success: false }); }
});

// AGREGAR nuevo item (autenticado)
app.post("/items/add", verificarToken, [
    body('title').trim().isLength({ min: 3, max: 200 }).withMessage('Título: 3-200 caracteres'),
    body('link').isURL().withMessage('Link debe ser URL válida'),
    body('image').optional().isURL().withMessage('Imagen debe ser URL válida'),
    body('description').optional().isLength({ max: 1000 }).withMessage('Descripción muy larga'),
    body('category').optional().trim(),
    body('tags').optional().isArray().withMessage('Tags debe ser array')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, error: "Datos inválidos", detalles: errors.array().map(e => e.msg) });
        const { title, description, image, link, category, tags } = req.body;
        const nuevoItem = new Juego({
            usuario: req.usuario,
            title: title.trim(),
            description: description?.trim() || '',
            image: image?.trim() || '',
            link: link.trim(),
            category: category?.trim() || 'General',
            tags: tags || [],
            status: "pendiente"
        });
        await nuevoItem.save();
        logger.info(`Usuario ${req.usuario} agregó item: ${title}`);
        res.status(201).json({ success: true, mensaje: "Item agregado (en revisión)", item: nuevoItem });
    } catch (e) { logger.error('❌ Error add item:', e); res.status(500).json({ success: false, error: "Error al guardar" }); }
});

// Aprobar item (ADMIN)
app.put("/items/approve/:id", verificarToken, verificarAdmin, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const item = await Juego.findByIdAndUpdate(req.params.id, { status: "aprobado" }, { new: true });
        if (!item) return res.status(404).json({ success: false, mensaje: "Item no encontrado" });
        logger.info(`Moderador ${req.usuario} aprobó: ${item.title}`);
        res.json({ success: true, mensaje: "Item aprobado", item });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Rechazar item (ADMIN)
app.put("/items/reject/:id", verificarToken, verificarAdmin, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const item = await Juego.findByIdAndUpdate(req.params.id, { status: "rechazado" }, { new: true });
        if (!item) return res.status(404).json({ success: false, mensaje: "Item no encontrado" });
        res.json({ success: true, mensaje: "Item rechazado", item });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Eliminar item
app.delete("/items/:id", verificarToken, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const item = await Juego.findById(req.params.id);
        if (!item) return res.status(404).json({ success: false, mensaje: "Item no encontrado" });
        if (item.usuario !== req.usuario && req.rol !== "admin" && req.rol !== "moderador") return res.status(403).json({ success: false, error: "Sin permiso" });
        await Juego.findByIdAndDelete(req.params.id);
        res.json({ success: true, mensaje: "Item eliminado" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Reportar item (autenticado)
app.put("/items/report/:id", verificarToken, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const item = await Juego.findByIdAndUpdate(req.params.id, { $inc: { reportes: 1 } }, { new: true });
        if (!item) return res.status(404).json({ success: false, mensaje: "Item no encontrado" });
        logger.warn(`${req.usuario} reportó: ${item.title} (Total: ${item.reportes})`);
        if (item.reportes >= 5 && item.status === 'aprobado') { item.status = 'rechazado'; await item.save(); logger.warn(`Auto-rechazado: ${item.title}`); }
        res.json({ success: true, reportes: item.reportes, mensaje: "Reporte registrado" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Like item (autenticado)
app.put("/items/like/:id", verificarToken, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const item = await Juego.findByIdAndUpdate(req.params.id, { $inc: { likes: 1 } }, { new: true });
        if (!item) return res.status(404).json({ success: false, mensaje: "Item no encontrado" });
        res.json({ success: true, likes: item.likes });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ========== COMENTARIOS ==========

// Obtener comentarios de un item
app.get("/comentarios/:itemId", async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const skip = (page - 1) * limit;
        const [comentarios, total] = await Promise.all([
            Comentario.find({ itemId: req.params.itemId }).sort({ createdAt: -1 }).limit(parseInt(limit)).skip(skip).lean(),
            Comentario.countDocuments({ itemId: req.params.itemId })
        ]);
        res.json({ success: true, comentarios, pagination: { total, page: parseInt(page), pages: Math.ceil(total / limit) } });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Agregar comentario (autenticado)
app.post("/comentarios", verificarToken, [
    body('texto').trim().isLength({ min: 1, max: 500 }).withMessage('Comentario: 1-500 caracteres'),
    body('itemId').notEmpty().withMessage('ItemId requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, error: "Texto inválido", detalles: errors.array().map(e => e.msg) });
        const nuevoComentario = new Comentario({ usuario: req.usuario, texto: req.body.texto.trim(), itemId: req.body.itemId });
        await nuevoComentario.save();
        logger.info(`${req.usuario} comentó en item ${req.body.itemId}`);
        res.status(201).json({ success: true, comentario: nuevoComentario });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Eliminar comentario (autenticado)
app.delete("/comentarios/:id", verificarToken, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const comentario = await Comentario.findById(req.params.id);
        if (!comentario) return res.status(404).json({ success: false, mensaje: "Comentario no encontrado" });
        if (comentario.usuario !== req.usuario && req.rol !== "admin" && req.rol !== "moderador") return res.status(403).json({ success: false, error: "Sin permiso" });
        await Comentario.findByIdAndDelete(req.params.id);
        res.json({ success: true, mensaje: "Comentario eliminado" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ========== FAVORITOS ==========

// Obtener favoritos de un usuario
app.get("/favoritos/:usuario", async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const skip = (page - 1) * limit;
        const [favoritos, total] = await Promise.all([
            Favorito.find({ usuario: req.params.usuario.toLowerCase() }).populate('itemId').sort({ createdAt: -1 }).limit(parseInt(limit)).skip(skip).lean(),
            Favorito.countDocuments({ usuario: req.params.usuario.toLowerCase() })
        ]);
        res.json({ success: true, favoritos, pagination: { total, page: parseInt(page), pages: Math.ceil(total / limit) } });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Agregar a favoritos (autenticado)
app.post("/favoritos/add", verificarToken, [body('itemId').isMongoId().withMessage('ItemId inválido')], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ItemId inválido" });
        const { itemId } = req.body;
        const itemExiste = await Juego.findById(itemId);
        if (!itemExiste) return res.status(404).json({ success: false, mensaje: "Item no encontrado" });
        const existe = await Favorito.findOne({ usuario: req.usuario, itemId });
        if (existe) return res.status(400).json({ success: false, mensaje: "Ya está en favoritos" });
        const nuevoFavorito = await Favorito.create({ usuario: req.usuario, itemId });
        res.status(201).json({ success: true, mensaje: "Agregado a favoritos", favorito: nuevoFavorito });
    } catch (e) {
        if (e.code === 11000) return res.status(400).json({ success: false, mensaje: "Ya está en favoritos" });
        res.status(500).json({ success: false });
    }
});

// Eliminar de favoritos (autenticado)
app.delete("/favoritos/delete/:id", verificarToken, [param('id').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ID inválido" });
        const favorito = await Favorito.findById(req.params.id);
        if (!favorito) return res.status(404).json({ success: false, mensaje: "Favorito no encontrado" });
        if (favorito.usuario !== req.usuario) return res.status(403).json({ success: false, error: "Sin permiso" });
        await Favorito.findByIdAndDelete(req.params.id);
        res.json({ success: true, mensaje: "Eliminado de favoritos" });
    } catch (e) { res.status(500).json({ success: false }); }
});

// Verificar si es favorito
app.get("/favoritos/check/:itemId", verificarToken, [param('itemId').isMongoId()], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, mensaje: "ItemId inválido" });
        const existe = await Favorito.findOne({ usuario: req.usuario, itemId: req.params.itemId });
        res.json({ success: true, esFavorito: !!existe, favoritoId: existe?._id || null });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ========== ESTADÍSTICAS (ADMIN) ==========
app.get("/admin/stats", verificarToken, verificarAdmin, async (req, res) => {
    try {
        const [totalUsuarios, totalItems, itemsPendientes, itemsAprobados, itemsRechazados, totalComentarios, totalFavoritos] = await Promise.all([
            Usuario.countDocuments(), Juego.countDocuments(),
            Juego.countDocuments({ status: 'pendiente' }), Juego.countDocuments({ status: 'aprobado' }),
            Juego.countDocuments({ status: 'rechazado' }), Comentario.countDocuments(), Favorito.countDocuments()
        ]);
        const topUsuarios = await Usuario.find().select('usuario listaSeguidores verificadoNivel avatar').sort({ createdAt: -1 }).limit(10).lean();
        const itemsReportados = await Juego.find({ reportes: { $gt: 0 } }).select('title usuario reportes status').sort({ reportes: -1 }).limit(10).lean();
        res.json({
            success: true,
            stats: {
                usuarios: { total: totalUsuarios },
                items: { total: totalItems, pendientes: itemsPendientes, aprobados: itemsAprobados, rechazados: itemsRechazados },
                interacciones: { comentarios: totalComentarios, favoritos: totalFavoritos },
                topUsuarios: topUsuarios.map(u => ({ ...u, seguidores: u.listaSeguidores ? u.listaSeguidores.length : 0 })),
                itemsReportados
            }
        });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ========== BÚSQUEDA GLOBAL ==========
app.get("/search", async (req, res) => {
    try {
        const { q, type = 'all', limit = 20 } = req.query;
        if (!q || q.trim().length < 2) return res.status(400).json({ success: false, mensaje: "Búsqueda mínimo 2 caracteres" });
        const searchQuery = q.trim();
        let results = {};
        if (type === 'all' || type === 'usuarios') {
            results.usuarios = await Usuario.find({ usuario: { $regex: searchQuery, $options: 'i' } }).select('usuario avatar verificadoNivel listaSeguidores').limit(parseInt(limit)).lean();
            results.usuarios = results.usuarios.map(u => ({ ...u, seguidores: u.listaSeguidores ? u.listaSeguidores.length : 0 }));
        }
        if (type === 'all' || type === 'items') {
            results.items = await Juego.find({
                status: 'aprobado',
                $or: [{ title: { $regex: searchQuery, $options: 'i' } }, { description: { $regex: searchQuery, $options: 'i' } }, { tags: { $in: [new RegExp(searchQuery, 'i')] } }]
            }).limit(parseInt(limit)).lean();
        }
        res.json({ success: true, query: searchQuery, results });
    } catch (e) { res.status(500).json({ success: false }); }
});

// ========== HEALTH CHECK ==========
app.get("/health", (req, res) => {
    res.json({ success: true, status: "OK", timestamp: new Date().toISOString(), uptime: process.uptime(), mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

// ========== ERROR HANDLING ==========
app.use((err, req, res, next) => {
    logger.error(`Error no manejado en ${req.method} ${req.path}:`, { error: err.message, stack: err.stack });
    if (err.name === 'ValidationError') return res.status(400).json({ success: false, error: "Error de validación", detalles: Object.values(err.errors).map(e => e.message) });
    if (err.code === 11000) return res.status(400).json({ success: false, error: "Registro duplicado", campo: Object.keys(err.keyPattern)[0] });
    if (err.name === 'CastError') return res.status(400).json({ success: false, error: "ID inválido" });
    res.status(500).json({ success: false, error: "Error crítico del servidor" });
});

app.use((req, res) => res.status(404).json({ success: false, error: "Ruta no encontrada", path: req.path }));

// ========== SEÑALES DE TERMINACIÓN ==========
process.on('SIGTERM', async () => { logger.info('SIGTERM'); await mongoose.connection.close(); process.exit(0); });
process.on('SIGINT', async () => { logger.info('SIGINT'); await mongoose.connection.close(); process.exit(0); });
process.on('unhandledRejection', (r) => logger.error('Unhandled Rejection:', r));
process.on('uncaughtException', (e) => { logger.error('Uncaught Exception:', e); process.exit(1); });

// ========== INICIO ==========
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => { logger.info(`🚀 Servidor corriendo en puerto ${PORT}`); });

module.exports = app;
