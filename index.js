

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

// ========== CONFIGURACIÓN DE LOGS PROFESIONALES ==========
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// ========== CONFIGURACIÓN DE SEGURIDAD ==========
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

const allowedOrigins = [
    'https://roucedevstudio.github',
    'https://roucedevstudio.github.io',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:7700'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('CORS no permitido'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ========== RATE LIMITING INTELIGENTE ==========
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: "Demasiadas peticiones, intenta en 15 minutos" },
    standardHeaders: true,
    legacyHeaders: false
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: "Demasiados intentos de login, espera 15 minutos" },
    skipSuccessfulRequests: true
});

const createLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 50,
    message: { error: "Has alcanzado el límite de creación por hora" }
});

app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/items/add', createLimiter);
app.use(generalLimiter);

// ========== SISTEMA DE LOGS MEJORADO ==========
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const user = req.usuario || 'anónimo';
        const logData = {
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            status: res.statusCode,
            duration: `${duration}ms`,
            user,
            ip: req.ip
        };
        
        if (res.statusCode >= 400) {
            logger.error('Request error', logData);
        } else {
            logger.info('Request', logData);
        }
    });
    next();
});

// ========== CONEXIÓN MONGODB CON RETRY ==========
const connectDB = async () => {
    const maxRetries = 5;
    let retries = 0;

    while (retries < maxRetries) {
        try {
            await mongoose.connect(process.env.MONGODB_URI, {
                maxPoolSize: 10,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000,
            });
            logger.info('🚀 MONGODB CONECTADO EXITOSAMENTE');
            return;
        } catch (err) {
            retries++;
            logger.error(`❌ Error conectando a MongoDB (intento ${retries}/${maxRetries}):`, err.message);
            if (retries === maxRetries) {
                logger.error('❌ NO SE PUDO CONECTAR A MONGODB - SERVIDOR ABORTADO');
                process.exit(1);
            }
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
};

connectDB();

mongoose.connection.on('disconnected', () => {
    logger.warn('⚠️ MongoDB desconectado. Intentando reconectar...');
});

mongoose.connection.on('error', (err) => {
    logger.error('❌ Error en MongoDB:', err);
});

// ========== SCHEMAS CON VALIDACIÓN COMPLETA ==========

// SCHEMA: Juegos/Items
const JuegoSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: [true, 'Usuario es requerido'],
        index: true,
        trim: true
    },
    title: { 
        type: String, 
        required: [true, 'Título es requerido'],
        maxlength: [200, 'Título muy largo'],
        trim: true,
        index: true
    },
    description: { 
        type: String, 
        maxlength: [1000, 'Descripción muy larga'],
        default: ''
    },
    image: { 
        type: String,
        validate: {
            validator: function(v) {
                return !v || /^https?:\/\/.+/.test(v);
            },
            message: 'URL de imagen inválida'
        }
    },
    link: { 
        type: String, 
        required: [true, 'Link es requerido'],
        validate: {
            validator: function(v) {
                return /^https?:\/\/.+/.test(v);
            },
            message: 'URL inválida'
        }
    },
    status: { 
        type: String, 
        enum: {
            values: ["pendiente", "aprobado", "rechazado"],
            message: 'Estado inválido'
        },
        default: "pendiente",
        index: true 
    },
    reportes: { 
        type: Number, 
        default: 0, 
        min: 0 
    },
    category: { 
        type: String, 
        default: "General",
        trim: true
    },
    tags: [{ 
        type: String, 
        maxlength: 30,
        trim: true
    }],
    vistas: { 
        type: Number, 
        default: 0 
    },
    likes: { 
        type: Number, 
        default: 0 
    }
}, { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

JuegoSchema.index({ usuario: 1, status: 1 });
JuegoSchema.index({ category: 1, status: 1 });
JuegoSchema.index({ createdAt: -1 });
JuegoSchema.index({ title: 'text', description: 'text' });

const Juego = mongoose.model('Juego', JuegoSchema);

// SCHEMA: Usuarios (SIN EMAIL OBLIGATORIO - PRIVACIDAD TOTAL)
const UsuarioSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: [true, 'Usuario es requerido'],
        unique: true,
        index: true,
        minlength: [3, 'Usuario muy corto'],
        maxlength: [20, 'Usuario muy largo'],
        trim: true,
        lowercase: true,
        validate: {
            validator: function(v) {
                return /^[a-z0-9_]+$/.test(v);
            },
            message: 'Usuario solo puede contener letras, números y guión bajo'
        }
    },
    password: { 
        type: String, 
        required: [true, 'Password es requerido'],
        minlength: [6, 'Password muy corto'],
        select: false
    },
    reputacion: { 
        type: Number, 
        default: 0,
        min: -1000,
        max: 10000
    },
listaSeguidores: [{
        type: String
    }],
    siguiendo: [{
        type: String
    }],
    verificadoNivel: { 
        type: Number, 
        default: 0, 
        min: 0, 
        max: 3,
        index: true
    },
    avatar: { 
        type: String, 
        default: "",
        validate: {
            validator: function(v) {
                return !v || /^https?:\/\/.+/.test(v);
            },
            message: 'URL de avatar inválida'
        }
    },
    bio: {
        type: String,
        maxlength: [200, 'Bio muy larga'],
        default: ''
    },
    rol: { 
        type: String, 
        enum: {
            values: ["usuario", "moderador", "admin"],
            message: 'Rol inválido'
        },
        default: "usuario",
        index: true
    },
    bloqueado: { 
        type: Boolean, 
        default: false,
        index: true
    },
    ultimoLogin: Date,
    intentosLoginFallidos: {
        type: Number,
        default: 0
    },
    bloqueoHasta: Date
}, { 
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

UsuarioSchema.index({ verificadoNivel: 1, seguidores: -1 });
UsuarioSchema.index({ rol: 1, bloqueado: 1 });

// Virtual para contar seguidores automáticamente
UsuarioSchema.virtual('seguidores').get(function() {
    return this.listaSeguidores ? this.listaSeguidores.length : 0;
});

// Virtual para contar siguiendo automáticamente
UsuarioSchema.virtual('cantidadSiguiendo').get(function() {
    return this.siguiendo ? this.siguiendo.length : 0;
});

UsuarioSchema.virtual('cantidadItems', {
    ref: 'Juego',
    localField: 'usuario',
    foreignField: 'usuario',
    count: true
});

UsuarioSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        this.password = await bcrypt.hash(this.password, 12);
        next();
    } catch (error) {
        next(error);
    }
});

UsuarioSchema.methods.compararPassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

UsuarioSchema.methods.actualizarVerificacionAuto = async function() {
    let nuevoNivel = 0;
    if (this.seguidores >= 1000) nuevoNivel = 3;
    else if (this.seguidores >= 100) nuevoNivel = 2;
    else if (this.seguidores >= 50) nuevoNivel = 1;

    if (nuevoNivel > this.verificadoNivel) {
        this.verificadoNivel = nuevoNivel;
        await this.save();
        logger.info(`Usuario ${this.usuario} subió a nivel ${nuevoNivel} de verificación`);
    }
};

UsuarioSchema.methods.generarToken = function() {
    return jwt.sign(
        { 
            id: this._id,
            usuario: this.usuario,
            rol: this.rol
        },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
};

UsuarioSchema.methods.generarRefreshToken = function() {
    return jwt.sign(
        { id: this._id },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '30d' }
    );
};

const Usuario = mongoose.model("Usuario", UsuarioSchema);

// SCHEMA: Comentarios
const ComentarioSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: [true, 'Usuario es requerido'],
        trim: true,
        index: true
    },
    texto: { 
        type: String, 
        required: [true, 'Texto es requerido'],
        maxlength: [500, 'Comentario muy largo'],
        trim: true
    },
    itemId: { 
        type: String, 
        required: [true, 'ItemId es requerido'],
        index: true
    },
    editado: {
        type: Boolean,
        default: false
    },
    likes: {
        type: Number,
        default: 0
    }
}, { 
    timestamps: true 
});

ComentarioSchema.index({ itemId: 1, createdAt: -1 });
const Comentario = mongoose.model('Comentario', ComentarioSchema);

// SCHEMA: Favoritos
const FavoritoSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: [true, 'Usuario es requerido'],
        index: true,
        trim: true
    },
    itemId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Juego',
        required: [true, 'ItemId es requerido'],
        index: true
    }
}, { 
    timestamps: true 
});

FavoritoSchema.index({ usuario: 1, itemId: 1 }, { unique: true });
const Favorito = mongoose.model('Favorito', FavoritoSchema);

// SCHEMA: Seguimiento de usuarios
const SeguimientoSchema = new mongoose.Schema({
    seguidor: { 
        type: String, 
        required: [true, 'Seguidor es requerido'],
        lowercase: true,
        trim: true,
        index: true
    },
    siguiendo: { 
        type: String, 
        required: [true, 'Siguiendo es requerido'],
        lowercase: true,
        trim: true,
        index: true
    }
}, { 
    timestamps: true 
});

// Índices para mejorar performance
SeguimientoSchema.index({ seguidor: 1, siguiendo: 1 }, { unique: true });
SeguimientoSchema.index({ seguidor: 1 });
SeguimientoSchema.index({ siguiendo: 1 });

const Seguimiento = mongoose.model('Seguimiento', SeguimientoSchema);

// SCHEMA: Refresh Tokens
const RefreshTokenSchema = new mongoose.Schema({
    token: {
        type: String,
        required: true,
        unique: true
    },
    usuarioId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Usuario',
        required: true
    },
    expiresAt: {
        type: Date,
        required: true
    }
}, { timestamps: true });

RefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);

// ========== MIDDLEWARES DE AUTENTICACIÓN ==========

const verificarToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                error: "Token requerido",
                codigo: "NO_TOKEN"
            });
        }

        const token = authHeader.split(' ')[1];

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            const usuario = await Usuario.findById(decoded.id)
                .select('-password')
                .lean();
            
            if (!usuario) {
                return res.status(401).json({ 
                    error: "Usuario no encontrado",
                    codigo: "USER_NOT_FOUND"
                });
            }

            if (usuario.bloqueado) {
                return res.status(403).json({ 
                    error: "Usuario bloqueado",
                    codigo: "USER_BLOCKED"
                });
            }

            req.usuario = usuario.usuario;
            req.usuarioId = usuario._id;
            req.rol = usuario.rol;
            req.usuarioCompleto = usuario;
            
            next();
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                return res.status(401).json({ 
                    error: "Token expirado",
                    codigo: "TOKEN_EXPIRED"
                });
            }
            return res.status(401).json({ 
                error: "Token inválido",
                codigo: "INVALID_TOKEN"
            });
        }
    } catch (error) {
        logger.error('Error en verificarToken:', error);
        res.status(500).json({ error: "Error de autenticación" });
    }
};

const verificarAdmin = (req, res, next) => {
    if (req.rol !== "admin" && req.rol !== "moderador") {
        return res.status(403).json({ 
            error: "Acceso denegado - Se requiere rol de administrador",
            codigo: "FORBIDDEN"
        });
    }
    next();
};

const verificarSoloAdmin = (req, res, next) => {
    if (req.rol !== "admin") {
        return res.status(403).json({ 
            error: "Acceso denegado - Solo administradores",
            codigo: "ADMIN_ONLY"
        });
    }
    next();
};

const verificarTokenOpcional = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return next();
        }

        const token = authHeader.split(' ')[1];

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const usuario = await Usuario.findById(decoded.id).select('-password').lean();
            
            if (usuario && !usuario.bloqueado) {
                req.usuario = usuario.usuario;
                req.usuarioId = usuario._id;
                req.rol = usuario.rol;
            }
        } catch (error) {
            // Token inválido, continuar sin error
        }
        
        next();
    } catch (error) {
        next();
    }
};

// ========== RUTAS DE AUTENTICACIÓN ==========

// REGISTRO (SIN EMAIL - PRIVACIDAD TOTAL)
app.post("/auth/register", [
    body('usuario')
        .trim()
        .toLowerCase()
        .isLength({ min: 3, max: 20 })
        .matches(/^[a-z0-9_]+$/)
        .withMessage('Usuario debe tener 3-20 caracteres (solo letras, números y _)'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password debe tener al menos 6 caracteres')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                errores: errors.array().map(e => e.msg)
            });
        }

        const { usuario, password } = req.body;

        const existeUsuario = await Usuario.findOne({ usuario: usuario.toLowerCase() });
        if (existeUsuario) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "El usuario ya existe" 
            });
        }

        const nuevoUsuario = new Usuario({ 
            usuario: usuario.toLowerCase(), 
            password
        });

        await nuevoUsuario.save();

        const token = nuevoUsuario.generarToken();
        const refreshToken = nuevoUsuario.generarRefreshToken();

        await RefreshToken.create({
            token: refreshToken,
            usuarioId: nuevoUsuario._id,
            expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        });

        logger.info(`✅ Nuevo usuario registrado: ${usuario}`);

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
        logger.error('❌ Error en registro:', error);
        
        if (error.code === 11000) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "El usuario ya existe" 
            });
        }
        
        res.status(500).json({ 
            success: false, 
            mensaje: "Error del servidor al registrar usuario" 
        });
    }
});

// ... debajo de app.post('/auth/register', ... )

// RUTA PARA CARGAR MAPA DE VERIFICACIÓN EN LA BIBLIOTECA
app.get('/auth/users', async (req, res) => {
    try {
        // Solo traemos el nombre de usuario y su nivel de verificado
        const usuarios = await Usuario.find({}, 'usuario verificadoNivel'); 
        res.json(usuarios);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ... arriba de app.post('/auth/login', ... )



// LOGIN
app.post("/auth/login", [
    body('usuario').trim().notEmpty().withMessage('Usuario requerido'),
    body('password').notEmpty().withMessage('Password requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Datos incompletos" 
            });
        }

        const { usuario, password } = req.body;

        const user = await Usuario.findOne({ 
            usuario: usuario.toLowerCase() 
        }).select('+password');

        if (!user) {
            return res.status(401).json({ 
                success: false, 
                mensaje: "Credenciales incorrectas",
                codigo: "INVALID_CREDENTIALS"
            });
        }

        if (user.bloqueoHasta && user.bloqueoHasta > new Date()) {
            const minutosRestantes = Math.ceil((user.bloqueoHasta - new Date()) / 60000);
            return res.status(403).json({
                success: false,
                mensaje: `Cuenta bloqueada temporalmente. Intenta en ${minutosRestantes} minutos`,
                codigo: "TEMP_BLOCKED"
            });
        }

        if (user.bloqueado) {
            return res.status(403).json({ 
                success: false, 
                mensaje: "Usuario bloqueado permanentemente. Contacta a soporte",
                codigo: "USER_BLOCKED"
            });
        }

        const passwordValida = await user.compararPassword(password);

        if (!passwordValida) {
            user.intentosLoginFallidos += 1;

            if (user.intentosLoginFallidos >= 5) {
                user.bloqueoHasta = new Date(Date.now() + 15 * 60 * 1000);
                user.intentosLoginFallidos = 0;
                await user.save();
                
                logger.warn(`⚠️ Usuario ${usuario} bloqueado temporalmente por intentos fallidos`);
                
                return res.status(403).json({
                    success: false,
                    mensaje: "Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos",
                    codigo: "TOO_MANY_ATTEMPTS"
                });
            }

            await user.save();

            return res.status(401).json({ 
                success: false, 
                mensaje: "Credenciales incorrectas",
                intentosRestantes: 5 - user.intentosLoginFallidos,
                codigo: "INVALID_CREDENTIALS"
            });
        }

        user.intentosLoginFallidos = 0;
        user.bloqueoHasta = undefined;
        user.ultimoLogin = new Date();
        await user.save();

        const token = user.generarToken();
        const refreshToken = user.generarRefreshToken();

        await RefreshToken.create({
            token: refreshToken,
            usuarioId: user._id,
            expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
        });

        logger.info(`✅ Login exitoso: ${usuario}`);

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
                seguidores: user.seguidores,
                bio: user.bio
            }
        });
    } catch (error) {
        logger.error('❌ Error en login:', error);
        res.status(500).json({ 
            success: false, 
            mensaje: "Error del servidor" 
        });
    }
});

// REFRESH TOKEN
app.post("/auth/refresh", [
    body('refreshToken').notEmpty().withMessage('Refresh token requerido')
], async (req, res) => {
    try {
        const { refreshToken } = req.body;

        const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
        
        if (!tokenDoc) {
            return res.status(401).json({ 
                success: false, 
                mensaje: "Refresh token inválido" 
            });
        }

        if (tokenDoc.expiresAt < new Date()) {
            await RefreshToken.deleteOne({ _id: tokenDoc._id });
            return res.status(401).json({ 
                success: false, 
                mensaje: "Refresh token expirado" 
            });
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

        const usuario = await Usuario.findById(decoded.id).select('-password');
        
        if (!usuario || usuario.bloqueado) {
            return res.status(401).json({ 
                success: false, 
                mensaje: "Usuario no válido" 
            });
        }

        const nuevoToken = usuario.generarToken();

        res.json({ 
            success: true,
            token: nuevoToken
        });
    } catch (error) {
        logger.error('❌ Error en refresh token:', error);
        res.status(401).json({ 
            success: false, 
            mensaje: "Refresh token inválido" 
        });
    }
});

// LOGOUT
app.post("/auth/logout", verificarToken, async (req, res) => {
    try {
        const { refreshToken } = req.body;
        
        if (refreshToken) {
            await RefreshToken.deleteOne({ token: refreshToken });
        }

        res.json({ 
            success: true, 
            mensaje: "Logout exitoso" 
        });
    } catch (error) {
        logger.error('❌ Error en logout:', error);
        res.status(500).json({ success: false });
    }
});

// VERIFICAR TOKEN
app.get("/auth/verify", verificarToken, async (req, res) => {
    res.json({ 
        success: true,
        usuario: req.usuarioCompleto
    });
});

// ========== RUTAS DE USUARIOS ==========

// Obtener perfil propio
app.get("/auth/me", verificarToken, async (req, res) => {
    try {
        const usuario = await Usuario.findById(req.usuarioId)
            .select('-password')
            .lean();

        const cantidadItems = await Juego.countDocuments({ 
            usuario: usuario.usuario,
            status: 'aprobado'
        });

        const cantidadFavoritos = await Favorito.countDocuments({ 
            usuario: usuario.usuario 
        });

        res.json({
            success: true,
            usuario: {
                ...usuario,
                cantidadItems,
                cantidadFavoritos
            }
        });
    } catch (error) {
        logger.error('❌ Error obteniendo perfil:', error);
        res.status(500).json({ success: false });
    }
});

// Obtener perfil de otro usuario
app.get("/auth/perfil/:usuario", async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ 
            usuario: req.params.usuario.toLowerCase() 
        })
        .select('-password')
        .lean();

        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        const cantidadItems = await Juego.countDocuments({ 
            usuario: usuario.usuario,
            status: 'aprobado'
        });

        const cantidadFavoritos = await Favorito.countDocuments({ 
            usuario: usuario.usuario 
        });

        res.json({
            success: true,
            usuario: {
                ...usuario,
                cantidadItems,
                cantidadFavoritos
            }
        });
    } catch (error) {
        logger.error('❌ Error obteniendo perfil:', error);
        res.status(500).json({ success: false });
    }
});

// Actualizar avatar
app.put("/auth/update-avatar", verificarToken, [
    body('nuevaFoto').isURL().withMessage('URL inválida')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "URL inválida" 
            });
        }

        const { nuevaFoto } = req.body;
        
        await Usuario.findOneAndUpdate(
            { usuario: req.usuario },
            { avatar: nuevaFoto }
        );

        logger.info(`Usuario ${req.usuario} actualizó su avatar`);

        res.json({ success: true });
    } catch (error) {
        logger.error('❌ Error actualizando avatar:', error);
        res.status(500).json({ success: false });
    }
});

// Actualizar bio
app.put("/auth/update-bio", verificarToken, [
    body('bio').trim().isLength({ max: 200 }).withMessage('Bio muy larga')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Bio muy larga (máximo 200 caracteres)" 
            });
        }

        const { bio } = req.body;
        
        await Usuario.findOneAndUpdate(
            { usuario: req.usuario },
            { bio }
        );

        res.json({ success: true });
    } catch (error) {
        logger.error('❌ Error actualizando bio:', error);
        res.status(500).json({ success: false });
    }
});

// SEGUIR/DEJAR DE SEGUIR
app.put("/auth/follow/:usuario", verificarToken, async (req, res) => {
    try {
        const target = req.params.usuario.toLowerCase();
        const seguidor = req.usuario;

        if (target === seguidor) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "No puedes seguirte a ti mismo" 
            });
        }

        const userTarget = await Usuario.findOne({ usuario: target });
        const userSeguidor = await Usuario.findOne({ usuario: seguidor });
        
        if (!userTarget) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        if (!userTarget.listaSeguidores) userTarget.listaSeguidores = [];
        if (!userSeguidor.siguiendo) userSeguidor.siguiendo = [];

        const yaEstaba = userTarget.listaSeguidores.includes(seguidor);
        
        if (yaEstaba) {
            userTarget.listaSeguidores = userTarget.listaSeguidores.filter(s => s !== seguidor);
            userSeguidor.siguiendo = userSeguidor.siguiendo.filter(s => s !== target);
        } else {
            userTarget.listaSeguidores.push(seguidor);
            userSeguidor.siguiendo.push(target);
        }

        userTarget.seguidores = userTarget.listaSeguidores.length;

        await userTarget.save();
        await userSeguidor.save();
        await userTarget.actualizarVerificacionAuto();

        logger.info(`${seguidor} ${yaEstaba ? 'dejó de seguir' : 'siguió'} a ${target}`);

        res.json({ 
            success: true,
            seguidores: userTarget.seguidores,
            verificadoNivel: userTarget.verificadoNivel,
            ahoraEstaSiguiendo: !yaEstaba
        });
    } catch (error) {
        logger.error('❌ Error en follow:', error);
        res.status(500).json({ success: false });
    }
});

// Obtener lista de seguidores
app.get("/auth/:usuario/seguidores", async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ 
            usuario: req.params.usuario.toLowerCase() 
        })
        .select('listaSeguidores')
        .lean();

        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        res.json({
            success: true,
            seguidores: usuario.listaSeguidores || []
        });
    } catch (error) {
        logger.error('❌ Error obteniendo seguidores:', error);
        res.status(500).json({ success: false });
    }
});

// Obtener lista de siguiendo
app.get("/auth/:usuario/siguiendo", async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ 
            usuario: req.params.usuario.toLowerCase() 
        })
        .select('siguiendo')
        .lean();

        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        res.json({
            success: true,
            siguiendo: usuario.siguiendo || []
        });
    } catch (error) {
        logger.error('❌ Error obteniendo siguiendo:', error);
        res.status(500).json({ success: false });
    }
});

// ============================================================================
// 🔥 COPIA ESTE CÓDIGO Y PÉGALO EN TU index.js 
// DESPUÉS DE LA LÍNEA 1101 (después de las rutas de seguimiento existentes)
// ============================================================================

// ========== RUTAS ALIAS PARA COMPATIBILIDAD CON FRONTEND ==========
// Estas rutas son "alias" de las rutas existentes pero con las URLs que espera el frontend


// ============================================================================
// 🔥 RUTAS DE SEGUIMIENTO CORREGIDAS Y OPTIMIZADAS
// ============================================================================

// 1. Seguir a un usuario
app.post("/usuarios/seguir", async (req, res) => {
    try {
        const { seguidor, siguiendo } = req.body;

        // Validaciones básicas
        if (!seguidor || !siguiendo) {
            return res.status(400).json({ 
                success: false, 
                message: "Faltan datos requeridos (seguidor y siguiendo)" 
            });
        }

        const seguidorLower = seguidor.toLowerCase().trim();
        const siguiendoLower = siguiendo.toLowerCase().trim();

        // No puede seguirse a sí mismo
        if (seguidorLower === siguiendoLower) {
            return res.status(400).json({ 
                success: false, 
                message: "No puedes seguirte a ti mismo" 
            });
        }

        // Buscar ambos usuarios
        const [usuarioSeguidor, usuarioSiguiendo] = await Promise.all([
            Usuario.findOne({ usuario: seguidorLower }),
            Usuario.findOne({ usuario: siguiendoLower })
        ]);
        
        if (!usuarioSiguiendo) {
            return res.status(404).json({ 
                success: false, 
                message: "El usuario que intentas seguir no existe" 
            });
        }

        if (!usuarioSeguidor) {
            return res.status(404).json({ 
                success: false, 
                message: "Tu usuario no existe" 
            });
        }

        // Verificar si ya lo sigue
        const yaSignue = await Seguimiento.findOne({
            seguidor: seguidorLower,
            siguiendo: siguiendoLower
        });

        if (yaSignue) {
            return res.status(400).json({ 
                success: false, 
                message: "Ya sigues a este usuario" 
            });
        }

        // Crear seguimiento en la colección Seguimiento
        await Seguimiento.create({
            seguidor: seguidorLower,
            siguiendo: siguiendoLower
        });

        // Actualizar arrays en los usuarios (para compatibilidad)
        if (!usuarioSiguiendo.listaSeguidores) usuarioSiguiendo.listaSeguidores = [];
        if (!usuarioSeguidor.siguiendo) usuarioSeguidor.siguiendo = [];

        // Agregar a arrays
        if (!usuarioSiguiendo.listaSeguidores.includes(seguidorLower)) {
            usuarioSiguiendo.listaSeguidores.push(seguidorLower);
        }
        usuarioSiguiendo.seguidores = usuarioSiguiendo.listaSeguidores.length;
        
        if (!usuarioSeguidor.siguiendo.includes(siguiendoLower)) {
            usuarioSeguidor.siguiendo.push(siguiendoLower);
        }

        // Guardar usuarios
        await Promise.all([
            usuarioSiguiendo.save(),
            usuarioSeguidor.save()
        ]);

        // Actualizar verificación automática si existe
        if (usuarioSiguiendo.actualizarVerificacionAuto) {
            try {
                await usuarioSiguiendo.actualizarVerificacionAuto();
            } catch (e) {
                logger.warn('No se pudo actualizar verificación automática');
            }
        }

        logger.info(`✅ ${seguidorLower} comenzó a seguir a ${siguiendoLower}`);

        res.status(201).json({ 
            success: true, 
            message: `Ahora sigues a @${siguiendo}`,
            seguidores: usuarioSiguiendo.seguidores,
            verificadoNivel: usuarioSiguiendo.verificadoNivel
        });

    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ 
                success: false, 
                message: "Ya sigues a este usuario" 
            });
        }
        logger.error('❌ Error al seguir usuario:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor al seguir usuario" 
        });
    }
});

// 2. Dejar de seguir a un usuario
app.delete("/usuarios/dejar-seguir", async (req, res) => {
    try {
        const { seguidor, siguiendo } = req.body;

        if (!seguidor || !siguiendo) {
            return res.status(400).json({ 
                success: false, 
                message: "Faltan datos requeridos (seguidor y siguiendo)" 
            });
        }

        const seguidorLower = seguidor.toLowerCase().trim();
        const siguiendoLower = siguiendo.toLowerCase().trim();

        // Eliminar de la colección Seguimiento
        const resultado = await Seguimiento.findOneAndDelete({
            seguidor: seguidorLower,
            siguiendo: siguiendoLower
        });

        if (!resultado) {
            return res.status(404).json({ 
                success: false, 
                message: "No seguías a este usuario" 
            });
        }

        // Actualizar arrays en los usuarios
        const [usuarioSeguidor, usuarioSiguiendo] = await Promise.all([
            Usuario.findOne({ usuario: seguidorLower }),
            Usuario.findOne({ usuario: siguiendoLower })
        ]);

        if (usuarioSiguiendo) {
            // Remover de listaSeguidores
            if (usuarioSiguiendo.listaSeguidores) {
                usuarioSiguiendo.listaSeguidores = usuarioSiguiendo.listaSeguidores.filter(
                    s => s !== seguidorLower
                );
                usuarioSiguiendo.seguidores = usuarioSiguiendo.listaSeguidores.length;
            } else {
                usuarioSiguiendo.seguidores = Math.max(0, (usuarioSiguiendo.seguidores || 1) - 1);
            }
            await usuarioSiguiendo.save();
        }

        if (usuarioSeguidor && usuarioSeguidor.siguiendo) {
            // Remover de siguiendo
            usuarioSeguidor.siguiendo = usuarioSeguidor.siguiendo.filter(
                s => s !== siguiendoLower
            );
            await usuarioSeguidor.save();
        }

        logger.info(`✅ ${seguidorLower} dejó de seguir a ${siguiendoLower}`);

        res.json({ 
            success: true, 
            message: `Dejaste de seguir a @${siguiendo}` 
        });

    } catch (error) {
        logger.error('❌ Error al dejar de seguir:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor" 
        });
    }
});

// 3. Obtener lista de usuarios que sigue alguien
app.get("/usuarios/siguiendo/:usuario", async (req, res) => {
    try {
        const usuario = req.params.usuario.toLowerCase().trim();

        // Buscar en la colección Seguimiento
        const seguimientos = await Seguimiento.find({ seguidor: usuario })
            .select('siguiendo')
            .lean();

        const listaSiguiendo = seguimientos.map(s => s.siguiendo);

        res.json({
            success: true,
            usuario: req.params.usuario,
            siguiendo: listaSiguiendo
        });

    } catch (error) {
        logger.error('❌ Error obteniendo siguiendo:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor" 
        });
    }
});

// 4. Obtener lista de seguidores de un usuario
app.get("/usuarios/seguidores/:usuario", async (req, res) => {
    try {
        const usuario = req.params.usuario.toLowerCase().trim();

        // Buscar en la colección Seguimiento
        const seguidores = await Seguimiento.find({ siguiendo: usuario })
            .select('seguidor')
            .lean();

        const listaSeguidores = seguidores.map(s => s.seguidor);

        res.json({
            success: true,
            usuario: req.params.usuario,
            seguidores: listaSeguidores
        });

    } catch (error) {
        logger.error('❌ Error obteniendo seguidores:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor" 
        });
    }
});

// 5. Verificar si un usuario sigue a otro
app.get("/usuarios/verifica-seguimiento/:seguidor/:siguiendo", async (req, res) => {
    try {
        const seguidor = req.params.seguidor.toLowerCase().trim();
        const siguiendo = req.params.siguiendo.toLowerCase().trim();

        const existe = await Seguimiento.findOne({
            seguidor,
            siguiendo
        });

        res.json({
            success: true,
            estaSiguiendo: !!existe
        });

    } catch (error) {
        logger.error('❌ Error verificando seguimiento:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor" 
        });
    }
});

// 6. Obtener estadísticas de seguimiento
app.get("/usuarios/stats-seguimiento/:usuario", async (req, res) => {
    try {
        const usuario = req.params.usuario.toLowerCase().trim();

        // Contar en la colección Seguimiento (más preciso)
        const [cantidadSiguiendo, cantidadSeguidores] = await Promise.all([
            Seguimiento.countDocuments({ seguidor: usuario }),
            Seguimiento.countDocuments({ siguiendo: usuario })
        ]);

        res.json({
            success: true,
            stats: {
                siguiendo: cantidadSiguiendo,
                seguidores: cantidadSeguidores
            }
        });

    } catch (error) {
        logger.error('❌ Error obteniendo estadísticas:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor" 
        });
    }
});

// 7. Actualizar perfil (avatar y bio)
app.put("/usuarios/actualizar-perfil", async (req, res) => {
    try {
        const { usuario, avatar, bio } = req.body;

        if (!usuario) {
            return res.status(400).json({ 
                success: false, 
                message: "Usuario requerido" 
            });
        }

        const user = await Usuario.findOne({ usuario: usuario.toLowerCase() });
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: "Usuario no encontrado" 
            });
        }

        // Actualizar avatar si se proporcionó
        if (avatar !== undefined) {
            user.avatar = avatar;
        }

        // Actualizar bio si se proporcionó
        if (bio !== undefined) {
            user.bio = bio;
        }

        await user.save();

        logger.info(`Usuario ${usuario} actualizó su perfil`);

        res.json({ 
            success: true,
            message: "Perfil actualizado correctamente",
            avatar: user.avatar,
            bio: user.bio
        });

    } catch (error) {
        logger.error('❌ Error actualizando perfil:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor" 
        });
    }
});


// Listar todos los usuarios (SOLO ADMIN)

// ========== RUTA PÚBLICA PARA OBTENER USUARIOS (SIN AUTENTICACIÓN) ==========
// Esta ruta es necesaria para que el frontend pueda obtener niveles de verificación
app.get("/auth/users-public", async (req, res) => {
    try {
        // Obtener todos los usuarios pero solo con campos públicos
        const usuarios = await Usuario.find({})
            .select('usuario verificadoNivel avatar bio seguidores')
            .lean();

        res.json(usuarios);
    } catch (error) {
        logger.error('❌ Error obteniendo usuarios públicos:', error);
        res.status(500).json({ 
            success: false, 
            message: "Error del servidor" 
        });
    }
});

app.get("/auth/users", verificarToken, verificarAdmin, async (req, res) => {
    try {
        const { 
            page = 1, 
            limit = 50, 
            search, 
            rol, 
            bloqueado 
        } = req.query;

        let query = {};
        
        if (search) {
            query.usuario = { $regex: search, $options: 'i' };
        }
        
        if (rol) {
            query.rol = rol;
        }
        
        if (bloqueado !== undefined) {
            query.bloqueado = bloqueado === 'true';
        }

        const skip = (page - 1) * limit;

        const [usuarios, total] = await Promise.all([
            Usuario.find(query)
                .select('-password')
                .sort({ seguidores: -1 })
                .limit(parseInt(limit))
                .skip(skip)
                .lean(),
            Usuario.countDocuments(query)
        ]);

        res.json({
            success: true,
            usuarios,
            pagination: {
                total,
                page: parseInt(page),
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        logger.error('❌ Error listando usuarios:', error);
        res.status(500).json({ success: false });
    }
});

// Eliminar usuario (SOLO ADMIN)
app.delete("/auth/users/:id", verificarToken, verificarSoloAdmin, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const usuario = await Usuario.findById(req.params.id);
        
        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        if (usuario.rol === 'admin' && req.usuarioId.toString() !== req.params.id) {
            return res.status(403).json({ 
                success: false, 
                mensaje: "No puedes eliminar otros administradores" 
            });
        }

        await Usuario.findByIdAndDelete(req.params.id);

        logger.warn(`Admin ${req.usuario} eliminó al usuario ${usuario.usuario}`);

        res.json({ 
            success: true, 
            mensaje: "Usuario eliminado" 
        });
    } catch (error) {
        logger.error('❌ Error eliminando usuario:', error);
        res.status(500).json({ success: false });
    }
});

// Bloquear/Desbloquear usuario (SOLO ADMIN)
app.put("/auth/users/:id/bloquear", verificarToken, verificarAdmin, [
    param('id').isMongoId().withMessage('ID inválido'),
    body('bloqueado').isBoolean().withMessage('Estado inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Datos inválidos" 
            });
        }

        const { bloqueado } = req.body;

        const usuario = await Usuario.findById(req.params.id);
        
        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        if (usuario.rol === 'admin') {
            return res.status(403).json({ 
                success: false, 
                mensaje: "No puedes bloquear administradores" 
            });
        }

        usuario.bloqueado = bloqueado;
        await usuario.save();

        logger.warn(`Admin ${req.usuario} ${bloqueado ? 'bloqueó' : 'desbloqueó'} a ${usuario.usuario}`);

        res.json({ 
            success: true,
            mensaje: `Usuario ${bloqueado ? 'bloqueado' : 'desbloqueado'}` 
        });
    } catch (error) {
        logger.error('❌ Error bloqueando usuario:', error);
        res.status(500).json({ success: false });
    }
});

// Cambiar verificación manual (SOLO ADMIN)
app.put("/auth/admin/verificacion/:usuario", verificarToken, verificarAdmin, [
    body('nivel').isInt({ min: 0, max: 3 }).withMessage('Nivel inválido (0-3)')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Nivel inválido (debe ser 0-3)" 
            });
        }

        const { nivel } = req.body;

        const user = await Usuario.findOneAndUpdate(
            { usuario: req.params.usuario.toLowerCase() },
            { verificadoNivel: nivel },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        logger.info(`Admin ${req.usuario} cambió verificación de ${user.usuario} a nivel ${nivel}`);

        res.json({ 
            success: true, 
            verificadoNivel: user.verificadoNivel 
        });
    } catch (error) {
        logger.error('❌ Error en verificación manual:', error);
        res.status(500).json({ success: false });
    }
});

// Cambiar rol de usuario (SOLO ADMIN)
app.put("/auth/admin/rol/:id", verificarToken, verificarSoloAdmin, [
    param('id').isMongoId().withMessage('ID inválido'),
    body('rol').isIn(['usuario', 'moderador', 'admin']).withMessage('Rol inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Datos inválidos" 
            });
        }

        const { rol } = req.body;

        const usuario = await Usuario.findByIdAndUpdate(
            req.params.id,
            { rol },
            { new: true }
        ).select('-password');

        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        logger.warn(`Admin ${req.usuario} cambió rol de ${usuario.usuario} a ${rol}`);

        res.json({ 
            success: true,
            usuario 
        });
    } catch (error) {
        logger.error('❌ Error cambiando rol:', error);
        res.status(500).json({ success: false });
    }
});

// ========== RUTAS DE ITEMS/JUEGOS ==========

// Listar items
app.get("/items", verificarTokenOpcional, async (req, res) => {
    try {
        const { 
            status = 'aprobado',
            usuario,
            category,
            search,
            limit = 50,
            page = 1,
            sortBy = 'createdAt',
            order = 'desc'
        } = req.query;

        let query = {};
        
        if (status) {
            query.status = status;
        }
        
        if (usuario) {
            query.usuario = usuario.toLowerCase();
        }
        
        if (category && category !== 'Todas') {
            query.category = category;
        }
        
        if (search) {
            query.$text = { $search: search };
        }

        const skip = (page - 1) * limit;
        const sortOrder = order === 'desc' ? -1 : 1;

        const [items, total] = await Promise.all([
            Juego.find(query)
                .sort({ [sortBy]: sortOrder })
                .limit(parseInt(limit))
                .skip(skip)
                .lean(),
            Juego.countDocuments(query)
        ]);

        res.json({
            success: true,
            items,
            pagination: {
                total,
                page: parseInt(page),
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        logger.error('❌ Error listando items:', error);
        res.status(500).json({ 
            success: false, 
            error: "Error interno" 
        });
    }
});

// Obtener items de un usuario
app.get("/items/user/:usuario", async (req, res) => {
    try {
        const { page = 1, limit = 50, status } = req.query;
        
        let query = { 
            usuario: req.params.usuario.toLowerCase() 
        };
        
        if (status) {
            query.status = status;
        }

        const skip = (page - 1) * limit;

        const [items, total] = await Promise.all([
            Juego.find(query)
                .sort({ createdAt: -1 })
                .limit(parseInt(limit))
                .skip(skip)
                .lean(),
            Juego.countDocuments(query)
        ]);

        res.json({
            success: true,
            items,
            pagination: {
                total,
                page: parseInt(page),
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        logger.error('❌ Error obteniendo items de usuario:', error);
        res.status(500).json({ success: false });
    }
});

// Obtener un item específico
app.get("/items/:id", verificarTokenOpcional, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const item = await Juego.findById(req.params.id).lean();
        
        if (!item) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Item no encontrado" 
            });
        }

        await Juego.findByIdAndUpdate(req.params.id, { $inc: { vistas: 1 } });

        res.json({
            success: true,
            item
        });
    } catch (error) {
        logger.error('❌ Error obteniendo item:', error);
        res.status(500).json({ success: false });
    }
});

// Agregar nuevo item
app.post("/items/add", verificarToken, [
    body('title')
        .trim()
        .isLength({ min: 3, max: 200 })
        .withMessage('Título debe tener 3-200 caracteres'),
    body('link')
        .isURL()
        .withMessage('Link debe ser una URL válida'),
    body('image')
        .optional()
        .isURL()
        .withMessage('Imagen debe ser una URL válida'),
    body('description')
        .optional()
        .isLength({ max: 1000 })
        .withMessage('Descripción muy larga'),
    body('category')
        .optional()
        .trim(),
    body('tags')
        .optional()
        .isArray()
        .withMessage('Tags debe ser un array')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false,
                error: "Datos inválidos", 
                detalles: errors.array().map(e => e.msg)
            });
        }

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

        res.status(201).json({ 
            success: true,
            mensaje: "Item agregado exitosamente (en revisión)",
            item: nuevoItem
        });
    } catch (error) {
        logger.error('❌ Error agregando item:', error);
        res.status(500).json({ 
            success: false,
            error: "Error al guardar item" 
        });
    }
});

// Aprobar item
app.put("/items/approve/:id", verificarToken, verificarAdmin, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const item = await Juego.findByIdAndUpdate(
            req.params.id,
            { status: "aprobado" },
            { new: true }
        );

        if (!item) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Item no encontrado" 
            });
        }

        logger.info(`Moderador ${req.usuario} aprobó item: ${item.title}`);

        res.json({ 
            success: true,
            mensaje: "Item aprobado",
            item 
        });
    } catch (error) {
        logger.error('❌ Error aprobando item:', error);
        res.status(500).json({ success: false });
    }
});

// Rechazar item
app.put("/items/reject/:id", verificarToken, verificarAdmin, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const item = await Juego.findByIdAndUpdate(
            req.params.id,
            { status: "rechazado" },
            { new: true }
        );

        if (!item) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Item no encontrado" 
            });
        }

        logger.info(`Moderador ${req.usuario} rechazó item: ${item.title}`);

        res.json({ 
            success: true,
            mensaje: "Item rechazado",
            item 
        });
    } catch (error) {
        logger.error('❌ Error rechazando item:', error);
        res.status(500).json({ success: false });
    }
});

// Eliminar item
app.delete("/items/:id", verificarToken, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const item = await Juego.findById(req.params.id);
        
        if (!item) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Item no encontrado" 
            });
        }

        if (item.usuario !== req.usuario && req.rol !== "admin" && req.rol !== "moderador") {
            return res.status(403).json({ 
                success: false,
                error: "No tienes permiso para eliminar este item" 
            });
        }

        await Juego.findByIdAndDelete(req.params.id);

        logger.info(`Usuario ${req.usuario} eliminó item: ${item.title}`);

        res.json({ 
            success: true,
            mensaje: "Item eliminado" 
        });
    } catch (error) {
        logger.error('❌ Error eliminando item:', error);
        res.status(500).json({ success: false });
    }
});

// Reportar item
app.put("/items/report/:id", verificarToken, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const item = await Juego.findByIdAndUpdate(
            req.params.id,
            { $inc: { reportes: 1 } },
            { new: true }
        );

        if (!item) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Item no encontrado" 
            });
        }

        logger.warn(`Usuario ${req.usuario} reportó item: ${item.title} (Total: ${item.reportes})`);

        if (item.reportes >= 5 && item.status === 'aprobado') {
            item.status = 'rechazado';
            await item.save();
            logger.warn(`Item auto-rechazado por reportes: ${item.title}`);
        }

        res.json({ 
            success: true,
            reportes: item.reportes,
            mensaje: "Reporte registrado" 
        });
    } catch (error) {
        logger.error('❌ Error reportando item:', error);
        res.status(500).json({ success: false });
    }
});

// Dar like
app.put("/items/like/:id", verificarToken, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const item = await Juego.findByIdAndUpdate(
            req.params.id,
            { $inc: { likes: 1 } },
            { new: true }
        );

        if (!item) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Item no encontrado" 
            });
        }

        res.json({ 
            success: true,
            likes: item.likes 
        });
    } catch (error) {
        logger.error('❌ Error dando like:', error);
        res.status(500).json({ success: false });
    }
});

// ========== COMENTARIOS ==========

// Obtener comentarios
app.get("/comentarios/:itemId", [
    param('itemId').notEmpty().withMessage('ItemId requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ItemId inválido" 
            });
        }

        const { page = 1, limit = 50 } = req.query;
        const skip = (page - 1) * limit;

        const [comentarios, total] = await Promise.all([
            Comentario.find({ itemId: req.params.itemId })
                .sort({ createdAt: -1 })
                .limit(parseInt(limit))
                .skip(skip)
                .lean(),
            Comentario.countDocuments({ itemId: req.params.itemId })
        ]);

        res.json({
            success: true,
            comentarios,
            pagination: {
                total,
                page: parseInt(page),
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        logger.error('❌ Error obteniendo comentarios:', error);
        res.status(500).json({ success: false });
    }
});

// Agregar comentario
app.post("/comentarios", verificarToken, [
    body('texto')
        .trim()
        .isLength({ min: 1, max: 500 })
        .withMessage('Comentario debe tener 1-500 caracteres'),
    body('itemId')
        .notEmpty()
        .withMessage('ItemId requerido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false,
                error: "Texto inválido",
                detalles: errors.array().map(e => e.msg)
            });
        }

        const { texto, itemId } = req.body;

        const nuevoComentario = new Comentario({ 
            usuario: req.usuario,
            texto: texto.trim(),
            itemId
        });

        await nuevoComentario.save();

        logger.info(`Usuario ${req.usuario} comentó en item ${itemId}`);

        res.status(201).json({ 
            success: true,
            comentario: nuevoComentario 
        });
    } catch (error) {
        logger.error('❌ Error agregando comentario:', error);
        res.status(500).json({ success: false });
    }
});

// Eliminar comentario
app.delete("/comentarios/:id", verificarToken, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const comentario = await Comentario.findById(req.params.id);
        
        if (!comentario) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Comentario no encontrado" 
            });
        }

        if (comentario.usuario !== req.usuario && req.rol !== "admin" && req.rol !== "moderador") {
            return res.status(403).json({ 
                success: false,
                error: "No tienes permiso para eliminar este comentario" 
            });
        }

        await Comentario.findByIdAndDelete(req.params.id);

        logger.info(`Usuario ${req.usuario} eliminó comentario`);

        res.json({ 
            success: true,
            mensaje: "Comentario eliminado" 
        });
    } catch (error) {
        logger.error('❌ Error eliminando comentario:', error);
        res.status(500).json({ success: false });
    }
});

// ========== FAVORITOS ==========

// Obtener favoritos
app.get("/favoritos/:usuario", async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const skip = (page - 1) * limit;

        const [favoritos, total] = await Promise.all([
            Favorito.find({ usuario: req.params.usuario.toLowerCase() })
                .populate('itemId')
                .sort({ createdAt: -1 })
                .limit(parseInt(limit))
                .skip(skip)
                .lean(),
            Favorito.countDocuments({ usuario: req.params.usuario.toLowerCase() })
        ]);

        res.json({
            success: true,
            favoritos,
            pagination: {
                total,
                page: parseInt(page),
                pages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        logger.error('❌ Error obteniendo favoritos:', error);
        res.status(500).json({ success: false });
    }
});

// Agregar a favoritos
app.post("/favoritos/add", verificarToken, [
    body('itemId').isMongoId().withMessage('ItemId inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ItemId inválido" 
            });
        }

        const { itemId } = req.body;

        const itemExiste = await Juego.findById(itemId);
        if (!itemExiste) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Item no encontrado" 
            });
        }

        const existe = await Favorito.findOne({ 
            usuario: req.usuario, 
            itemId 
        });

        if (existe) {
            return res.status(400).json({ 
                success: false,
                mensaje: "Ya está en favoritos" 
            });
        }

        const nuevoFavorito = await Favorito.create({ 
            usuario: req.usuario, 
            itemId 
        });

        logger.info(`Usuario ${req.usuario} agregó a favoritos: ${itemExiste.title}`);

        res.status(201).json({ 
            success: true,
            mensaje: "Agregado a favoritos",
            favorito: nuevoFavorito 
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({ 
                success: false,
                mensaje: "Ya está en favoritos" 
            });
        }
        logger.error('❌ Error agregando favorito:', error);
        res.status(500).json({ success: false });
    }
});

// Eliminar de favoritos
app.delete("/favoritos/delete/:id", verificarToken, [
    param('id').isMongoId().withMessage('ID inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ID inválido" 
            });
        }

        const favorito = await Favorito.findById(req.params.id);
        
        if (!favorito) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Favorito no encontrado" 
            });
        }

        if (favorito.usuario !== req.usuario) {
            return res.status(403).json({ 
                success: false,
                error: "No tienes permiso" 
            });
        }

        await Favorito.findByIdAndDelete(req.params.id);

        logger.info(`Usuario ${req.usuario} eliminó favorito`);

        res.json({ 
            success: true,
            mensaje: "Eliminado de favoritos" 
        });
    } catch (error) {
        logger.error('❌ Error eliminando favorito:', error);
        res.status(500).json({ success: false });
    }
});

// Verificar si es favorito
app.get("/favoritos/check/:itemId", verificarToken, [
    param('itemId').isMongoId().withMessage('ItemId inválido')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "ItemId inválido" 
            });
        }

        const existe = await Favorito.findOne({ 
            usuario: req.usuario,
            itemId: req.params.itemId
        });

        res.json({
            success: true,
            esFavorito: !!existe,
            favoritoId: existe?._id || null
        });
    } catch (error) {
        logger.error('❌ Error verificando favorito:', error);
        res.status(500).json({ success: false });
    }
});

// ========== ESTADÍSTICAS ==========
app.get("/admin/stats", verificarToken, verificarAdmin, async (req, res) => {
    try {
        const [
            totalUsuarios,
            totalItems,
            itemsPendientes,
            itemsAprobados,
            itemsRechazados,
            totalComentarios,
            totalFavoritos
        ] = await Promise.all([
            Usuario.countDocuments(),
            Juego.countDocuments(),
            Juego.countDocuments({ status: 'pendiente' }),
            Juego.countDocuments({ status: 'aprobado' }),
            Juego.countDocuments({ status: 'rechazado' }),
            Comentario.countDocuments(),
            Favorito.countDocuments()
        ]);

        const topUsuarios = await Usuario.find()
            .select('usuario seguidores verificadoNivel avatar')
            .sort({ seguidores: -1 })
            .limit(10)
            .lean();

        const itemsReportados = await Juego.find({ reportes: { $gt: 0 } })
            .select('title usuario reportes status')
            .sort({ reportes: -1 })
            .limit(10)
            .lean();

        res.json({
            success: true,
            stats: {
                usuarios: {
                    total: totalUsuarios
                },
                items: {
                    total: totalItems,
                    pendientes: itemsPendientes,
                    aprobados: itemsAprobados,
                    rechazados: itemsRechazados
                },
                interacciones: {
                    comentarios: totalComentarios,
                    favoritos: totalFavoritos
                },
                topUsuarios,
                itemsReportados
            }
        });
    } catch (error) {
        logger.error('❌ Error obteniendo estadísticas:', error);
        res.status(500).json({ success: false });
    }
});

// ========== BÚSQUEDA GLOBAL ==========
app.get("/search", async (req, res) => {
    try {
        const { q, type = 'all', limit = 20 } = req.query;

        if (!q || q.trim().length < 2) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Búsqueda muy corta (mínimo 2 caracteres)" 
            });
        }

        const searchQuery = q.trim();
        let results = {};

        if (type === 'all' || type === 'usuarios') {
            results.usuarios = await Usuario.find({ 
                usuario: { $regex: searchQuery, $options: 'i' }
            })
            .select('usuario avatar verificadoNivel seguidores')
            .limit(parseInt(limit))
            .lean();
        }

        if (type === 'all' || type === 'items') {
            results.items = await Juego.find({
                status: 'aprobado',
                $or: [
                    { title: { $regex: searchQuery, $options: 'i' } },
                    { description: { $regex: searchQuery, $options: 'i' } },
                    { tags: { $in: [new RegExp(searchQuery, 'i')] } }
                ]
            })
            .limit(parseInt(limit))
            .lean();
        }

        res.json({
            success: true,
            query: searchQuery,
            results
        });
    } catch (error) {
        logger.error('❌ Error en búsqueda:', error);
        res.status(500).json({ success: false });
    }
});


// ========== SISTEMA DE SEGUIDORES (FOLLOW / UNFOLLOW) ==========

// 1. SEGUIR a un usuario
app.post('/usuarios/seguir', verificarToken, async (req, res) => {
    try {
        const { seguidor, siguiendo } = req.body;
        
        logger.info(`Intento de seguir: ${seguidor} -> ${siguiendo}`);
        
        // Validaciones
        if (!seguidor || !siguiendo) {
            return res.status(400).json({
                success: false,
                message: "Faltan parámetros requeridos"
            });
        }
        
        if (seguidor === siguiendo) {
            return res.status(400).json({
                success: false,
                message: "No puedes seguirte a ti mismo"
            });
        }
        
        // Verificar que el usuario autenticado coincida con el seguidor
        if (req.usuario !== seguidor) {
            return res.status(403).json({
                success: false,
                message: "No autorizado"
            });
        }
        
        // Buscar usuarios
        const [usuarioSeguidor, usuarioSiguiendo] = await Promise.all([
            Usuario.findOne({ usuario: seguidor }),
            Usuario.findOne({ usuario: siguiendo })
        ]);
        
        if (!usuarioSeguidor || !usuarioSiguiendo) {
            return res.status(404).json({
                success: false,
                message: "Usuario no encontrado"
            });
        }
        
        // Verificar si ya lo sigue
        const yaLoSigue = usuarioSiguiendo.listaSeguidores.includes(seguidor);
        
        if (yaLoSigue) {
            return res.status(400).json({
                success: false,
                message: "Ya sigues a este usuario"
            });
        }
        
        // Agregar a las listas
        usuarioSiguiendo.listaSeguidores.push(seguidor);
        usuarioSeguidor.siguiendo.push(siguiendo);
        
        // Guardar cambios
        await Promise.all([
            usuarioSeguidor.save(),
            usuarioSiguiendo.save()
        ]);
        
        logger.info(`✅ ${seguidor} ahora sigue a ${siguiendo}`);
        
        res.json({
            success: true,
            message: `Ahora sigues a ${siguiendo}`,
            seguidores: usuarioSiguiendo.listaSeguidores.length,
            siguiendo: usuarioSeguidor.siguiendo.length
        });
        
    } catch (error) {
        logger.error('❌ Error al seguir usuario:', error);
        res.status(500).json({
            success: false,
            message: "Error al seguir usuario",
            error: error.message
        });
    }
});

// 2. DEJAR DE SEGUIR a un usuario
app.delete('/usuarios/dejar-seguir', verificarToken, async (req, res) => {
    try {
        const { seguidor, siguiendo } = req.body;
        
        logger.info(`Intento de dejar de seguir: ${seguidor} -> ${siguiendo}`);
        
        // Validaciones
        if (!seguidor || !siguiendo) {
            return res.status(400).json({
                success: false,
                message: "Faltan parámetros requeridos"
            });
        }
        
        // Verificar que el usuario autenticado coincida con el seguidor
        if (req.usuario !== seguidor) {
            return res.status(403).json({
                success: false,
                message: "No autorizado"
            });
        }
        
        // Buscar usuarios
        const [usuarioSeguidor, usuarioSiguiendo] = await Promise.all([
            Usuario.findOne({ usuario: seguidor }),
            Usuario.findOne({ usuario: siguiendo })
        ]);
        
        if (!usuarioSeguidor || !usuarioSiguiendo) {
            return res.status(404).json({
                success: false,
                message: "Usuario no encontrado"
            });
        }
        
        // Remover de las listas
        usuarioSiguiendo.listaSeguidores = usuarioSiguiendo.listaSeguidores.filter(u => u !== seguidor);
        usuarioSeguidor.siguiendo = usuarioSeguidor.siguiendo.filter(u => u !== siguiendo);
        
        // Guardar cambios
        await Promise.all([
            usuarioSeguidor.save(),
            usuarioSiguiendo.save()
        ]);
        
        logger.info(`✅ ${seguidor} dejó de seguir a ${siguiendo}`);
        
        res.json({
            success: true,
            message: `Dejaste de seguir a ${siguiendo}`,
            seguidores: usuarioSiguiendo.listaSeguidores.length,
            siguiendo: usuarioSeguidor.siguiendo.length
        });
        
    } catch (error) {
        logger.error('❌ Error al dejar de seguir:', error);
        res.status(500).json({
            success: false,
            message: "Error al dejar de seguir",
            error: error.message
        });
    }
});

// 3. OBTENER lista de usuarios que sigue
app.get('/usuarios/siguiendo/:usuario', async (req, res) => {
    try {
        const { usuario } = req.params;
        
        const user = await Usuario.findOne({ usuario });
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Usuario no encontrado"
            });
        }
        
        res.json({
            success: true,
            siguiendo: user.siguiendo || []
        });
        
    } catch (error) {
        logger.error('❌ Error obteniendo siguiendo:', error);
        res.status(500).json({
            success: false,
            message: "Error al obtener datos"
        });
    }
});

// 4. OBTENER estadísticas de seguimiento
app.get('/usuarios/stats-seguimiento/:usuario', async (req, res) => {
    try {
        const { usuario } = req.params;
        
        const user = await Usuario.findOne({ usuario });
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "Usuario no encontrado"
            });
        }
        
        res.json({
            success: true,
            stats: {
                seguidores: user.listaSeguidores ? user.listaSeguidores.length : 0,
                siguiendo: user.siguiendo ? user.siguiendo.length : 0
            }
        });
        
    } catch (error) {
        logger.error('❌ Error obteniendo stats:', error);
        res.status(500).json({
            success: false,
            message: "Error al obtener estadísticas"
        });
    }
});

// 5. TOGGLE SEGUIR (ruta legacy - mantener por compatibilidad)
app.post('/usuarios/toggle-seguir', verificarToken, async (req, res) => {
    const { usuarioDestino, seguidor } = req.body;
    
    if (usuarioDestino === seguidor) {
        return res.status(400).json({ success: false, mensaje: "No puedes seguirte a ti mismo" });
    }
    
    try {
        const objetivo = await Usuario.findOne({ usuario: usuarioDestino });
        const yo = await Usuario.findOne({ usuario: seguidor });
        
        if (!objetivo || !yo) {
            return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        }
        
        const yaLoSigo = objetivo.listaSeguidores.includes(seguidor);
        
        if (yaLoSigo) {
            objetivo.listaSeguidores = objetivo.listaSeguidores.filter(u => u !== seguidor);
            yo.siguiendo = yo.siguiendo.filter(u => u !== usuarioDestino);
        } else {
            objetivo.listaSeguidores.push(seguidor);
            yo.siguiendo.push(usuarioDestino);
        }
        
        await objetivo.save();
        await yo.save();
        
        res.json({
            success: true,
            siguiendo: !yaLoSigo,
            seguidoresCount: objetivo.listaSeguidores.length,
            siguiendoCount: yo.siguiendo.length
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});
// 1. Seguir a un usuario

// ========== HEALTH CHECK ==========
app.get("/health", (req, res) => {
    res.json({ 
        success: true,
        status: "OK",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    });
});

// ========== MANEJO DE ERRORES ==========
app.use((err, req, res, next) => {
    logger.error(`Error no manejado en ${req.method} ${req.path}:`, {
        error: err.message,
        stack: err.stack,
        body: req.body
    });

    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: "Error de validación",
            detalles: Object.values(err.errors).map(e => e.message)
        });
    }

    if (err.code === 11000) {
        return res.status(400).json({
            success: false,
            error: "Registro duplicado",
            campo: Object.keys(err.keyPattern)[0]
        });
    }

    if (err.name === 'CastError') {
        return res.status(400).json({
            success: false,
            error: "ID inválido"
        });
    }

    res.status(500).json({ 
        success: false,
        error: "Error crítico del servidor" 
    });
});

app.use((req, res) => {
    res.status(404).json({ 
        success: false,
        error: "Ruta no encontrada",
        path: req.path
    });
});

// ========== SEÑALES DE TERMINACIÓN ==========
process.on('SIGTERM', async () => {
    logger.info('SIGTERM recibido. Cerrando servidor...');
    await mongoose.connection.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    logger.info('SIGINT recibido. Cerrando servidor...');
    await mongoose.connection.close();
    process.exit(0);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', { reason, promise });
});

process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    process.exit(1);
});

// ========== INICIO DEL SERVIDOR ==========
const PORT = process.env.PORT || 10000;

app.listen(PORT, '0.0.0.0', () => {
    logger.info(`

    `);
});

module.exports = app;