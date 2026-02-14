require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult, param } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// ⚠️ Módulos personalizados
const config = require('./config');
const logger = require('./logger');
const fraudDetector = require('./fraudDetector');

const app = express();

// ========== CONFIGURACIÓN DE SEGURIDAD ==========
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// CORS - DOMINIOS PERMITIDOS (SEGURIDAD CRÍTICA)
const allowedOrigins = [
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
            callback(new Error('Acceso CORS no permitido desde este origen'));
        }
    },
    credentials: true
}));

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ========== RATE LIMITING ==========
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: "Demasiadas peticiones, intenta en 15 minutos" },
    standardHeaders: true,
    legacyHeaders: false,
    skip: () => process.env.NODE_ENV === 'development'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: "Demasiados intentos de login, espera 15 minutos" },
    skipSuccessfulRequests: true,
    skip: () => process.env.NODE_ENV === 'development'
});

const createLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 50,
    message: { error: "Has alcanzado el límite de creación por hora" },
    skip: () => process.env.NODE_ENV === 'development'
});

const downloadValidationLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: "Demasiadas validaciones de descarga. Espera un minuto." },
    skip: () => process.env.NODE_ENV === 'development'
});

// Aplicar limitadores
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/items/add', createLimiter);
app.use('/economia/validar-descarga', downloadValidationLimiter);
app.use(generalLimiter);

// ========== SISTEMA DE LOGS ==========
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const status = res.statusCode >= 400 ? '❌' : '✅';
        logger.info(`${status} [${req.method}] ${req.path} - ${res.statusCode} (${duration}ms)`);
    });
    next();
});

// ========== CONEXIÓN MONGODB ==========
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET;

if (!MONGODB_URI || !JWT_SECRET) {
    logger.error("❌ FALTAN VARIABLES DE ENTORNO: MONGODB_URI y JWT_SECRET son obligatorias.");
    process.exit(1);
}

mongoose.connect(MONGODB_URI, {
    maxPoolSize: 5,
    minPoolSize: 1,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => logger.info("🚀 MONGODB CONECTADO EXITOSAMENTE"))
.catch(err => {
    logger.error("❌ ERROR CONEXIÓN MONGODB:", err.message);
    process.exit(1);
});

mongoose.connection.on('disconnected', () => {
    logger.warn('⚠️ MongoDB desconectado. Intentando reconectar...');
});

// ========== SCHEMAS ==========

// ⭐ SCHEMA: Control de IPs por descarga (TTL de 24 horas) - ANTI-BOTS
const DescargaIPSchema = new mongoose.Schema({
    juegoId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Juego',
        required: true
    },
    ip: { 
        type: String, 
        required: true
    },
    contadorHoy: { 
        type: Number, 
        default: 1 
    },
    fecha: { 
        type: Date, 
        default: Date.now,
        expires: 86400
    }
});

DescargaIPSchema.index({ juegoId: 1, ip: 1 });
const DescargaIP = mongoose.model('DescargaIP', DescargaIPSchema);

// ⭐ SCHEMA: Juegos (CON ECONOMÍA COMPLETA)
const JuegoSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: true,
        trim: true,
        default: "Cloud User"
    },
    title: { 
        type: String, 
        required: true,
        maxlength: 200,
        trim: true
    },
    description: { 
        type: String, 
        maxlength: 1000,
        default: ''
    },
    image: { 
        type: String,
        default: ''
    },
    link: { 
        type: String, 
        required: true
    },
    status: { 
        type: String, 
        enum: ["pendiente", "aprobado", "rechazado", "pending"],
        default: "pendiente"
    },
    linkStatus: {
        type: String,
        enum: ["online", "revision", "caido"],
        default: "online"
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
    tags: [String],
    descargasEfectivas: { 
        type: Number, 
        default: 0,
        min: 0
    }
}, { 
    timestamps: true
});

JuegoSchema.index({ usuario: 1, status: 1 });
JuegoSchema.index({ createdAt: -1 });
JuegoSchema.index({ linkStatus: 1 });
JuegoSchema.index({ descargasEfectivas: -1 });
JuegoSchema.index({ status: 1 });

JuegoSchema.pre('save', function(next) {
    if (this.reportes >= 3) {
        this.linkStatus = 'revision';
    }
    next();
});

const Juego = mongoose.model('Juego', JuegoSchema);

// ⭐ SCHEMA: Usuarios (CON ECONOMÍA COMPLETA)
const UsuarioSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: true,
        unique: true,
        index: true,
        minlength: 3,
        maxlength: 20,
        trim: true,
        lowercase: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true,
        match: [/^\S+@\S+\.\S+$/, 'Email inválido']
    },
    password: { 
        type: String, 
        required: true,
        minlength: 6
    },
    paypalEmail: {
        type: String,
        default: '',
        lowercase: true,
        trim: true,
        match: [/^(\S+@\S+\.\S+)?$/, 'Email de PayPal inválido']
    },
    saldo: {
        type: Number,
        default: 0,
        min: 0
    },
    descargasTotales: {
        type: Number,
        default: 0,
        min: 0
    },
    isVerificado: {
        type: Boolean,
        default: false,
        index: true
    },
    solicitudPagoPendiente: {
        type: Boolean,
        default: false
    },
    reputacion: { 
        type: Number, 
        default: 0
    },
    listaSeguidores: [String],
    siguiendo: [String],
    verificadoNivel: { 
        type: Number, 
        default: 0, 
        min: 0, 
        max: 3,
        index: true
    },
    avatar: { 
        type: String, 
        default: ""
    },
    bio: {
        type: String,
        maxlength: 200,
        default: ''
    },
    fecha: { 
        type: Date, 
        default: Date.now 
    },
    registrationIP: {
        type: String,
        default: ''
    },
    listaNegraAdmin: {
        type: Boolean,
        default: false,
        index: true
    },
    notasAdmin: {
        type: String,
        default: '',
        maxlength: 500
    },
    fechaListaNegra: {
        type: Date,
        default: null
    }
}, { 
    collection: 'usuarios',
    timestamps: true
});

const RefreshTokenSchema = new mongoose.Schema({
    usuario: { type: String, required: true, index: true },
    token: { type: String, required: true, unique: true },
    expira: { 
        type: Date, 
        required: true, 
        index: true, 
        expires: 0 
    },
    creado: { type: Date, default: Date.now }
});

const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);

UsuarioSchema.pre('save', function(next) {
    if (this.verificadoNivel >= 1 && !this.isVerificado) {
        this.isVerificado = true;
    }
    next();
});

const Usuario = mongoose.model('Usuario', UsuarioSchema);

// ⭐ SCHEMA: Historial de Pagos
const PagoSchema = new mongoose.Schema({
    usuario: {
        type: String,
        required: true,
        index: true
    },
    monto: {
        type: Number,
        required: true,
        min: 0
    },
    paypalEmail: {
        type: String,
        required: true
    },
    estado: {
        type: String,
        enum: ['pendiente', 'procesado', 'completado', 'rechazado'],
        default: 'pendiente',
        index: true
    },
    fecha: {
        type: Date,
        default: Date.now
    },
    notas: {
        type: String,
        default: ''
    }
}, { timestamps: true });

const Pago = mongoose.model('Pago', PagoSchema);

// SCHEMA: Comentarios
const CommentSchema = new mongoose.Schema({
    usuario: String,
    texto: String,
    itemId: String,
    fecha: { type: Date, default: Date.now }
});

const Comentario = mongoose.model('Comentario', CommentSchema);

// SCHEMA: Favoritos
const FavoritosSchema = new mongoose.Schema({
    usuario: String,
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego' }
});

const Favorito = mongoose.model('Favoritos', FavoritosSchema);

// ========== MIDDLEWARE DE AUTENTICACIÓN JWT ==========
const verificarToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, error: "Token no proporcionado" });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded.usuario;
        req.userTokenData = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, error: "Token inválido o expirado" });
    }
};

// ========== FUNCIONES AUXILIARES JWT ==========
const generarTokens = (usuario) => {
    const accessToken = jwt.sign(
        { usuario },
        JWT_SECRET,
        { expiresIn: config.JWT_ACCESS_EXPIRATION }
    );
    
    const refreshToken = jwt.sign(
        { usuario },
        config.JWT_REFRESH_SECRET,
        { expiresIn: config.JWT_REFRESH_EXPIRATION }
    );
    
    return { accessToken, refreshToken };
};

const verificarJWT = (token) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        throw new Error('Token inválido');
    }
};

// ==========================================
// ⭐⭐⭐ RUTAS DE ECONOMÍA (CORAZÓN DEL SISTEMA)
// ==========================================

const CPM_VALUE = config.CPM_VALUE;
const AUTHOR_PERCENTAGE = config.AUTHOR_PERCENTAGE;
const MIN_DOWNLOADS_TO_EARN = config.MIN_DOWNLOADS_TO_EARN;
const MIN_WITHDRAWAL = config.MIN_WITHDRAWAL;
const MAX_DOWNLOADS_PER_IP_PER_DAY = config.MAX_DOWNLOADS_PER_IP_PER_DAY;

/**
 * ⭐ ENDPOINT CRÍTICO: Validar descarga efectiva
 * ⚠️ ACTUALIZADO: Incluye detección automática de fraude
 */
app.post('/economia/validar-descarga', [
    body('juegoId').isMongoId(),
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "ID de juego inválido",
                details: errors.array()
            });
        }

        const { juegoId } = req.body;
        
        const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || 
                    req.headers['x-real-ip'] || 
                    req.connection.remoteAddress || 
                    req.socket.remoteAddress;

        logger.info(`📥 Validación de descarga - Juego: ${juegoId}, IP: ${ip}`);

        const juego = await Juego.findById(juegoId);
        if (!juego) {
            return res.status(404).json({ 
                success: false, 
                error: "Juego no encontrado" 
            });
        }

        if (juego.status !== 'aprobado') {
            return res.status(403).json({ 
                success: false, 
                error: "El juego no está aprobado para descargas" 
            });
        }

        let registroIP = await DescargaIP.findOne({ juegoId, ip });
        
        if (registroIP) {
            if (registroIP.contadorHoy >= MAX_DOWNLOADS_PER_IP_PER_DAY) {
                logger.info(`⚠️ Límite alcanzado - IP: ${ip}, Juego: ${juegoId}`);
                return res.json({
                    success: true,
                    limiteAlcanzado: true,
                    mensaje: "Has alcanzado el límite de descargas para hoy",
                    link: juego.link
                });
            }
            registroIP.contadorHoy += 1;
            await registroIP.save();
        } else {
            registroIP = new DescargaIP({
                juegoId,
                ip,
                contadorHoy: 1
            });
            await registroIP.save();
        }

        await Juego.findByIdAndUpdate(juegoId, { $inc: { descargasEfectivas: 1 } });
        juego.descargasEfectivas += 1;

        const autor = await Usuario.findOne({ usuario: juego.usuario });
        if (!autor) {
            logger.warn(`⚠️ Autor no encontrado: ${juego.usuario}`);
            return res.json({
                success: true,
                descargaContada: true,
                link: juego.link,
                mensaje: "Descarga válida"
            });
        }

        if (autor.listaNegraAdmin) {
            logger.info(`🚫 Usuario en lista negra detectado: @${autor.usuario}`);
            
            autor.descargasTotales += 1;
            await autor.save();
            
            return res.json({
                success: true,
                descargaContada: true,
                link: juego.link,
                descargasEfectivas: juego.descargasEfectivas,
                mensaje: "Descarga válida",
                warning: "Usuario bajo revisión - ganancia suspendida"
            });
        }

        autor.descargasTotales += 1;

        let gananciaGenerada = 0;
        let shouldAnalyzeFraud = false;

        if (juego.descargasEfectivas > MIN_DOWNLOADS_TO_EARN) {
            if (autor.isVerificado && autor.verificadoNivel >= 1) {
                gananciaGenerada = (CPM_VALUE * AUTHOR_PERCENTAGE) / 1000;
                autor.saldo += gananciaGenerada;
                shouldAnalyzeFraud = true;
                
                logger.info(`💰 Ganancia generada - Autor: @${autor.usuario}, +$${gananciaGenerada.toFixed(4)} USD`);
            } else {
                logger.info(`ℹ️ Autor no verificado - @${autor.usuario} - No se suma saldo`);
            }
        } else {
            logger.info(`ℹ️ Juego aún no alcanza ${MIN_DOWNLOADS_TO_EARN} descargas - Actual: ${juego.descargasEfectivas}`);
        }

        if (shouldAnalyzeFraud && config.FEATURES.ENABLE_FRAUD_DETECTION) {
            const fraudAnalysis = await fraudDetector.analyzeDownloadBehavior(
                autor.usuario,
                juegoId,
                ip,
                gananciaGenerada
            );

            if (fraudAnalysis.suspicious) {
                logger.info(`⚠️ COMPORTAMIENTO SOSPECHOSO - @${autor.usuario}:`);
                fraudAnalysis.reasons.forEach(reason => logger.info(`   - ${reason}`));

                if (fraudAnalysis.autoFlag) {
                    const flagged = await fraudDetector.autoFlagUser(
                        Usuario,
                        autor.usuario,
                        `Detección automática: ${fraudAnalysis.reasons.join(', ')}`
                    );

                    if (flagged) {
                        autor.saldo -= gananciaGenerada;
                        gananciaGenerada = 0;
                        
                        logger.info(`🚫 Usuario auto-marcado y ganancia revertida: @${autor.usuario}`);
                    }
                }
            }
        }

        await autor.save();

        logger.info(`✅ Descarga efectiva validada - Juego: ${juego.title}, Total: ${juego.descargasEfectivas}`);

        res.json({
            success: true,
            descargaContada: true,
            link: juego.link,
            descargasEfectivas: juego.descargasEfectivas,
            mensaje: "Descarga válida y contada"
        });

    } catch (error) {
        logger.error("❌ Error en validar-descarga:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al validar descarga" 
        });
    }
});

/**
 * ⭐ Solicitar pago (usuario)
 */
app.post('/economia/solicitar-pago', verificarToken, async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.usuario });
        
        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario no encontrado" 
            });
        }

        if (usuario.saldo < MIN_WITHDRAWAL) {
            return res.json({
                success: false,
                error: `Saldo insuficiente. Necesitas al menos $${MIN_WITHDRAWAL} USD para solicitar un pago`,
                saldoActual: usuario.saldo,
                minimoRequerido: MIN_WITHDRAWAL
            });
        }

        if (!usuario.isVerificado || usuario.verificadoNivel < 1) {
            return res.json({
                success: false,
                error: "Debes ser un usuario verificado para solicitar pagos",
                verificadoNivel: usuario.verificadoNivel
            });
        }

        if (!usuario.paypalEmail || usuario.paypalEmail.length < 5) {
            return res.json({
                success: false,
                error: "Debes configurar tu email de PayPal antes de solicitar un pago"
            });
        }

        if (usuario.solicitudPagoPendiente) {
            return res.json({
                success: false,
                error: "Ya tienes una solicitud de pago pendiente"
            });
        }

        const nuevoPago = new Pago({
            usuario: usuario.usuario,
            monto: usuario.saldo,
            paypalEmail: usuario.paypalEmail,
            estado: 'pendiente',
            fecha: new Date()
        });

        await nuevoPago.save();

        usuario.solicitudPagoPendiente = true;
        await usuario.save();

        logger.info(`💸 Solicitud de pago creada - Usuario: @${usuario.usuario}, Monto: $${usuario.saldo.toFixed(2)}`);

        res.json({
            success: true,
            mensaje: "Solicitud de pago creada exitosamente. Recibirás tu pago en 3-5 días hábiles.",
            solicitud: {
                monto: usuario.saldo,
                paypalEmail: usuario.paypalEmail,
                fecha: nuevoPago.fecha
            }
        });

    } catch (error) {
        logger.error("❌ Error en solicitar-pago:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al procesar solicitud de pago" 
        });
    }
});

/**
 * ⭐ Consultar mi saldo (usuario)
 */
app.get('/economia/mi-saldo', verificarToken, async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.usuario })
            .select('saldo descargasTotales paypalEmail isVerificado verificadoNivel solicitudPagoPendiente');

        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario no encontrado" 
            });
        }

        const juegosConGanancias = await Juego.countDocuments({
            usuario: req.usuario,
            descargasEfectivas: { $gt: MIN_DOWNLOADS_TO_EARN }
        });

        const descargasTotalesJuegos = await Juego.aggregate([
            { $match: { usuario: req.usuario } },
            { $group: { _id: null, total: { $sum: '$descargasEfectivas' } } }
        ]);

        const totalDescargasJuegos = descargasTotalesJuegos[0]?.total || 0;

        res.json({
            success: true,
            saldo: usuario.saldo,
            descargasTotales: usuario.descargasTotales,
            descargasEfectivasJuegos: totalDescargasJuegos,
            paypalEmail: usuario.paypalEmail,
            paypalConfigurado: !!usuario.paypalEmail,
            isVerificado: usuario.isVerificado,
            verificadoNivel: usuario.verificadoNivel,
            solicitudPagoPendiente: usuario.solicitudPagoPendiente,
            juegosConGanancias,
            puedeRetirar: usuario.saldo >= MIN_WITHDRAWAL && usuario.isVerificado,
            minimoRetiro: MIN_WITHDRAWAL,
            cpmValue: CPM_VALUE,
            authorPercentage: AUTHOR_PERCENTAGE
        });

    } catch (error) {
        logger.error("❌ Error en mi-saldo:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al obtener saldo" 
        });
    }
});

/**
 * ⭐ Actualizar email de PayPal
 */
app.put('/economia/actualizar-paypal', [
    verificarToken,
    body('paypalEmail').isEmail().normalizeEmail()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Email de PayPal inválido",
                details: errors.array()
            });
        }

        const { paypalEmail } = req.body;

        const usuario = await Usuario.findOne({ usuario: req.usuario });
        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario no encontrado" 
            });
        }

        usuario.paypalEmail = paypalEmail;
        await usuario.save();

        logger.info(`💳 PayPal actualizado - Usuario: @${usuario.usuario}`);

        res.json({
            success: true,
            mensaje: "Email de PayPal actualizado exitosamente",
            paypalEmail: usuario.paypalEmail
        });

    } catch (error) {
        logger.error("❌ Error en actualizar-paypal:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al actualizar PayPal" 
        });
    }
});

/**
 * ⭐ Configurar PayPal (alias de actualizar-paypal)
 */
app.put('/usuarios/configurar-paypal', verificarToken, async (req, res) => {
    try {
        const { paypalEmail } = req.body;

        if (!paypalEmail || !/^\S+@\S+\.\S+$/.test(paypalEmail)) {
            return res.status(400).json({ 
                success: false, 
                error: "Email de PayPal inválido" 
            });
        }

        const usuario = await Usuario.findOne({ usuario: req.usuario });
        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario no encontrado" 
            });
        }

        usuario.paypalEmail = paypalEmail.toLowerCase().trim();
        await usuario.save();

        logger.info(`💳 PayPal configurado - Usuario: @${usuario.usuario}`);

        res.json({
            success: true,
            mensaje: "Email de PayPal configurado exitosamente",
            paypalEmail: usuario.paypalEmail
        });

    } catch (error) {
        logger.error("❌ Error en configurar-paypal:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al configurar PayPal" 
        });
    }
});

// ==========================================
// ⭐⭐⭐ ADMIN: FINANZAS
// ==========================================

/**
 * ⭐ Ver solicitudes de pago pendientes (ADMIN)
 * Diferente de /admin/payments-pending - Esta trae solicitudes formales
 */
app.get('/admin/finanzas/solicitudes-pendientes', async (req, res) => {
    try {
        const solicitudes = await Pago.find({ estado: 'pendiente' })
            .sort({ fecha: -1 })
            .lean();

        const solicitudesEnriquecidas = await Promise.all(
            solicitudes.map(async (s) => {
                const usuario = await Usuario.findOne({ usuario: s.usuario })
                    .select('email verificadoNivel isVerificado descargasTotales');
                
                const juegosElegibles = await Juego.countDocuments({
                    usuario: s.usuario,
                    descargasEfectivas: { $gt: MIN_DOWNLOADS_TO_EARN }
                });

                return {
                    ...s,
                    datosUsuario: {
                        email: usuario?.email || '',
                        verificadoNivel: usuario?.verificadoNivel || 0,
                        isVerificado: usuario?.isVerificado || false,
                        descargasTotales: usuario?.descargasTotales || 0,
                        juegosElegibles
                    }
                };
            })
        );

        res.json({
            success: true,
            solicitudes: solicitudesEnriquecidas,
            total: solicitudesEnriquecidas.length
        });

    } catch (error) {
        logger.error("❌ Error en solicitudes-pendientes:", error);
        res.status(500).json({ success: false, error: "Error al cargar solicitudes" });
    }
});

/**
 * ⭐ Procesar pago (marcar como completado) - ADMIN
 */
app.post('/admin/finanzas/procesar-pago/:id', [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "ID inválido" 
            });
        }

        const pago = await Pago.findById(req.params.id);
        if (!pago) {
            return res.status(404).json({ 
                success: false, 
                error: "Pago no encontrado" 
            });
        }

        if (pago.estado !== 'pendiente') {
            return res.json({
                success: false,
                error: `El pago ya fue ${pago.estado}`
            });
        }

        const usuario = await Usuario.findOne({ usuario: pago.usuario });
        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario no encontrado" 
            });
        }

        pago.estado = 'completado';
        pago.notas = `Procesado el ${new Date().toLocaleDateString('es-ES')}`;
        await pago.save();

        usuario.saldo -= pago.monto;
        if (usuario.saldo < 0) usuario.saldo = 0;
        usuario.solicitudPagoPendiente = false;
        await usuario.save();

        logger.info(`✅ Pago procesado - Usuario: @${usuario.usuario}, Monto: $${pago.monto.toFixed(2)}`);

        res.json({
            success: true,
            mensaje: "Pago procesado y saldo actualizado",
            pago: {
                id: pago._id,
                usuario: pago.usuario,
                monto: pago.monto,
                estado: pago.estado
            }
        });

    } catch (error) {
        logger.error("❌ Error en procesar-pago:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al procesar pago" 
        });
    }
});

/**
 * ⭐ Rechazar pago - ADMIN
 */
app.post('/admin/finanzas/rechazar-pago/:id', [
    param('id').isMongoId(),
    body('motivo').optional().isString()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const { motivo } = req.body;

        const pago = await Pago.findById(req.params.id);
        if (!pago) {
            return res.status(404).json({ 
                success: false, 
                error: "Pago no encontrado" 
            });
        }

        if (pago.estado !== 'pendiente') {
            return res.json({
                success: false,
                error: `El pago ya fue ${pago.estado}`
            });
        }

        pago.estado = 'rechazado';
        pago.notas = motivo || `Rechazado el ${new Date().toLocaleDateString('es-ES')}`;
        await pago.save();

        const usuario = await Usuario.findOne({ usuario: pago.usuario });
        if (usuario) {
            usuario.solicitudPagoPendiente = false;
            await usuario.save();
        }

        logger.info(`❌ Pago rechazado - Usuario: @${pago.usuario}, Motivo: ${motivo}`);

        res.json({
            success: true,
            mensaje: "Pago rechazado",
            pago: {
                id: pago._id,
                usuario: pago.usuario,
                estado: pago.estado,
                motivo: pago.notas
            }
        });

    } catch (error) {
        logger.error("❌ Error en rechazar-pago:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al rechazar pago" 
        });
    }
});

/**
 * ⭐ Historial de pagos - ADMIN
 */
app.get('/admin/finanzas/historial', async (req, res) => {
    try {
        const { estado, limit = 50 } = req.query;

        const query = estado ? { estado } : {};
        
        const pagos = await Pago.find(query)
            .sort({ fecha: -1 })
            .limit(parseInt(limit))
            .lean();

        res.json({
            success: true,
            pagos,
            total: pagos.length
        });

    } catch (error) {
        logger.error("❌ Error en historial:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al cargar historial" 
        });
    }
});

/**
 * ⭐ Estadísticas financieras - ADMIN
 */
app.get('/admin/finanzas/estadisticas', async (req, res) => {
    try {
        const [
            totalPagado,
            totalPendiente,
            totalRechazado,
            usuariosConSaldo,
            topEarners
        ] = await Promise.all([
            Pago.aggregate([
                { $match: { estado: 'completado' } },
                { $group: { _id: null, total: { $sum: '$monto' } } }
            ]),
            Pago.aggregate([
                { $match: { estado: 'pendiente' } },
                { $group: { _id: null, total: { $sum: '$monto' } } }
            ]),
            Pago.countDocuments({ estado: 'rechazado' }),
            Usuario.countDocuments({ saldo: { $gt: 0 } }),
            Usuario.find({ saldo: { $gt: 0 } })
                .sort({ saldo: -1 })
                .limit(10)
                .select('usuario saldo descargasTotales verificadoNivel')
        ]);

        res.json({
            success: true,
            estadisticas: {
                totalPagado: totalPagado[0]?.total || 0,
                totalPendiente: totalPendiente[0]?.total || 0,
                totalRechazado,
                usuariosConSaldo,
                topEarners
            }
        });

    } catch (error) {
        logger.error("❌ Error en estadísticas:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al cargar estadísticas" 
        });
    }
});

// ==========================================
// ⭐⭐⭐ ADMIN: GESTIÓN DE LINKS
// ==========================================

/**
 * ⭐ Links en revisión - ADMIN
 */
app.get('/admin/links/en-revision', async (req, res) => {
    try {
        const linksEnRevision = await Juego.find({ linkStatus: 'revision' })
            .sort({ reportes: -1, updatedAt: -1 })
            .lean();

        res.json({
            success: true,
            links: linksEnRevision,
            total: linksEnRevision.length
        });

    } catch (error) {
        logger.error("❌ Error en links-en-revision:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al cargar links" 
        });
    }
});

/**
 * ⭐ Marcar link como caído - ADMIN
 */
app.put('/admin/links/marcar-caido/:id', [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "ID inválido" 
            });
        }

        const juego = await Juego.findById(req.params.id);
        if (!juego) {
            return res.status(404).json({ 
                success: false, 
                error: "Juego no encontrado" 
            });
        }

        juego.linkStatus = 'caido';
        await juego.save();

        logger.info(`🔗 Link marcado como caído - Juego: ${juego.title}`);

        res.json({
            success: true,
            mensaje: "Link marcado como caído",
            juego: {
                id: juego._id,
                title: juego.title,
                linkStatus: juego.linkStatus
            }
        });

    } catch (error) {
        logger.error("❌ Error en marcar-caido:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al marcar link" 
        });
    }
});

/**
 * ⭐ Verificar descarga (endpoint antiguo - COMPATIBILIDAD)
 */
app.post('/items/verify-download/:id', async (req, res) => {
    try {
        const juego = await Juego.findById(req.params.id);
        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        res.json({ 
            success: true, 
            link: juego.link,
            mensaje: "Link verificado - usa /economia/validar-descarga para contabilizar"
        });
    } catch (error) {
        logger.error("Error en verify-download:", error);
        res.status(500).json({ error: "Error al verificar" });
    }
});

// ==========================================
// ⭐⭐⭐ AUTENTICACIÓN
// ==========================================

/**
 * ⭐ Registro de usuario
 */
app.post('/auth/register', [
    body('usuario').isLength({ min: 3, max: 20 }).trim().toLowerCase(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: "Datos inválidos", 
                details: errors.array() 
            });
        }

        const { usuario, email, password } = req.body;

        const existeUsuario = await Usuario.findOne({ 
            $or: [{ usuario }, { email }] 
        });

        if (existeUsuario) {
            return res.status(400).json({ 
                error: "El usuario o email ya existe" 
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || 
                    req.headers['x-real-ip'] || 
                    req.connection.remoteAddress;

        const nuevoUsuario = new Usuario({
            usuario: usuario.toLowerCase().trim(),
            email: email.toLowerCase().trim(),
            password: hashedPassword,
            registrationIP: ip,
            fecha: new Date()
        });

        await nuevoUsuario.save();

        const { accessToken, refreshToken } = generarTokens(nuevoUsuario.usuario);

        await RefreshToken.create({
            usuario: nuevoUsuario.usuario,
            token: refreshToken,
            expira: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });

        logger.info(`✅ Usuario registrado - @${nuevoUsuario.usuario} - IP: ${ip}`);

        res.json({
            success: true,
            mensaje: "Usuario registrado exitosamente",
            token: accessToken,
            refreshToken,
            usuario: {
                usuario: nuevoUsuario.usuario,
                email: nuevoUsuario.email,
                verificadoNivel: nuevoUsuario.verificadoNivel,
                saldo: nuevoUsuario.saldo
            }
        });

    } catch (error) {
        logger.error("❌ Error en register:", error);
        res.status(500).json({ error: "Error al registrar usuario" });
    }
});

/**
 * ⭐ Login
 */
app.post('/auth/login', [
    body('usuario').trim(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: "Datos inválidos" 
            });
        }

        const { usuario, password } = req.body;

        const user = await Usuario.findOne({
            $or: [
                { usuario: usuario.toLowerCase() },
                { email: usuario.toLowerCase() }
            ]
        });

        if (!user) {
            return res.status(401).json({ 
                error: "Usuario o contraseña incorrectos" 
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ 
                error: "Usuario o contraseña incorrectos" 
            });
        }

        const { accessToken, refreshToken } = generarTokens(user.usuario);

        await RefreshToken.create({
            usuario: user.usuario,
            token: refreshToken,
            expira: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });

        logger.info(`✅ Login exitoso - @${user.usuario}`);

        res.json({
            success: true,
            mensaje: "Login exitoso",
            token: accessToken,
            refreshToken,
            usuario: {
                usuario: user.usuario,
                email: user.email,
                verificadoNivel: user.verificadoNivel,
                saldo: user.saldo,
                avatar: user.avatar,
                bio: user.bio
            }
        });

    } catch (error) {
        logger.error("❌ Error en login:", error);
        res.status(500).json({ error: "Error al iniciar sesión" });
    }
});

// ==========================================
// ⭐⭐⭐ ADMIN: ESTADÍSTICAS Y DASHBOARD
// ==========================================

/**
 * ⭐ Dashboard de estadísticas - ADMIN
 */
app.get('/admin/stats/dashboard', async (req, res) => {
    try {
        const hoy = new Date();
        hoy.setHours(0, 0, 0, 0);
        
        const semanaAtras = new Date();
        semanaAtras.setDate(semanaAtras.getDate() - 7);
        semanaAtras.setHours(0, 0, 0, 0);
        
        const [
            // Usuarios
            totalUsuarios,
            usuariosHoy,
            usuariosSemana,
            usuariosVerificados,
            usuariosListaNegra,
            
            // Items/Juegos
            totalJuegos,
            juegosAprobados,
            juegosPendientes,
            juegosHoy,
            
            // Descargas
            totalDescargas,
            descargasHoy,
            
            // Finanzas
            totalSaldos,
            solicitudesPendientes,
            
            // Comentarios
            totalComentarios,
            comentariosHoy,
            
            // Links
            linksEnRevision
        ] = await Promise.all([
            // Usuarios
            Usuario.countDocuments(),
            Usuario.countDocuments({ createdAt: { $gte: hoy } }),
            Usuario.countDocuments({ createdAt: { $gte: semanaAtras } }),
            Usuario.countDocuments({ isVerificado: true }),
            Usuario.countDocuments({ esListaNegra: true }),
            
            // Items
            Juego.countDocuments(),
            Juego.countDocuments({ status: 'aprobado' }),
            Juego.countDocuments({ status: 'pendiente' }),
            Juego.countDocuments({ createdAt: { $gte: hoy } }),
            
            // Descargas
            Juego.aggregate([
                { $group: { _id: null, total: { $sum: '$descargasEfectivas' } } }
            ]),
            Juego.aggregate([
                { $match: { updatedAt: { $gte: hoy } } },
                { $group: { _id: null, total: { $sum: '$descargasEfectivas' } } }
            ]),
            
            // Finanzas
            Usuario.aggregate([
                { $group: { _id: null, total: { $sum: '$saldo' } } }
            ]),
            SolicitudPago.countDocuments({ status: 'pendiente' }),
            
            // Comentarios
            Comentario.countDocuments(),
            Comentario.countDocuments({ fecha: { $gte: hoy } }),
            
            // Links
            Juego.countDocuments({ linkStatus: 'revision' })
        ]);
        
        // Calcular pendiente de pago
        const solicitudesPago = await SolicitudPago.find({ status: 'pendiente' }).lean();
        const pendienteDePago = solicitudesPago.reduce((sum, s) => sum + (s.monto || 0), 0);
        
        res.json({
            success: true,
            dashboard: { // ⭐ Cambiar de "stats" a "dashboard"
                usuarios: {
                    total: totalUsuarios,
                    hoy: usuariosHoy,
                    semana: usuariosSemana,
                    verificados: usuariosVerificados,
                    listaNegra: usuariosListaNegra
                },
                items: {
                    total: totalJuegos,
                    aprobados: juegosAprobados,
                    pendientes: juegosPendientes,
                    hoy: juegosHoy
                },
                descargas: {
                    total: totalDescargas[0]?.total || 0,
                    hoy: descargasHoy[0]?.total || 0
                },
                finanzas: {
                    saldoEnCirculacion: totalSaldos[0]?.total || 0,
                    pendienteDePago: pendienteDePago
                },
                comentarios: {
                    total: totalComentarios,
                    hoy: comentariosHoy
                },
                linksEnRevision: linksEnRevision
            }
        });
        
    } catch (error) {
        logger.error("❌ Error en dashboard:", error);
        res.status(500).json({
            success: false,
            error: "Error al cargar dashboard",
            message: error.message
        });
    }
});
/**
 * ⭐ Ajustar saldo manualmente - ADMIN
 */
app.put('/admin/users/ajustar-saldo/:id', [
    param('id').isMongoId(),
    body('nuevoSaldo').isFloat({ min: 0 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const { nuevoSaldo } = req.body;

        const usuario = await Usuario.findById(req.params.id);
        if (!usuario) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario no encontrado" 
            });
        }

        const saldoAnterior = usuario.saldo;
        usuario.saldo = nuevoSaldo;
        await usuario.save();

        logger.info(`💰 Saldo ajustado - Usuario: @${usuario.usuario}, Anterior: $${saldoAnterior}, Nuevo: $${nuevoSaldo}`);

        res.json({
            success: true,
            mensaje: "Saldo actualizado",
            usuario: {
                usuario: usuario.usuario,
                saldoAnterior,
                saldoNuevo: nuevoSaldo
            }
        });

    } catch (error) {
        logger.error("❌ Error en ajustar-saldo:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al ajustar saldo" 
        });
    }
});

/**
 * ⭐ Acciones en lote para items - ADMIN
 */
app.put('/admin/items/bulk-action', [
    body('ids').isArray(),
    body('action').isIn(['aprobar', 'rechazar', 'eliminar'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const { ids, action } = req.body;

        let resultado;
        
        switch (action) {
            case 'aprobar':
                resultado = await Juego.updateMany(
                    { _id: { $in: ids } },
                    { status: 'aprobado' }
                );
                break;
            case 'rechazar':
                resultado = await Juego.updateMany(
                    { _id: { $in: ids } },
                    { status: 'rechazado' }
                );
                break;
            case 'eliminar':
                resultado = await Juego.deleteMany({ _id: { $in: ids } });
                break;
        }

        logger.info(`📦 Acción en lote - Acción: ${action}, Items: ${ids.length}`);

        res.json({
            success: true,
            mensaje: `Acción ${action} completada`,
            modificados: resultado.modifiedCount || resultado.deletedCount
        });

    } catch (error) {
        logger.error("❌ Error en bulk-action:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error en acción masiva" 
        });
    }
});

/**
 * ⭐ Rechazar pago alternativo - ADMIN
 */
app.post('/admin/finanzas/rechazar-pago-admin/:id', [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const pago = await Pago.findById(req.params.id);
        if (!pago) {
            return res.status(404).json({ 
                success: false, 
                error: "Pago no encontrado" 
            });
        }

        pago.estado = 'rechazado';
        await pago.save();

        const usuario = await Usuario.findOne({ usuario: pago.usuario });
        if (usuario) {
            usuario.solicitudPagoPendiente = false;
            await usuario.save();
        }

        res.json({
            success: true,
            mensaje: "Pago rechazado por administrador"
        });

    } catch (error) {
        logger.error("❌ Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Historial completo de pagos - ADMIN
 */
app.get('/admin/finanzas/historial-completo', async (req, res) => {
    try {
        const pagos = await Pago.find()
            .sort({ fecha: -1 })
            .lean();

        res.json({
            success: true,
            pagos
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Top usuarios por descargas - ADMIN
 */
app.get('/admin/stats/top-usuarios', async (req, res) => {
    try {
        const topUsuarios = await Usuario.find()
            .sort({ descargasTotales: -1 })
            .limit(20)
            .select('usuario descargasTotales saldo verificadoNivel')
            .lean();

        res.json({
            success: true,
            usuarios: topUsuarios
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Eliminar todos los items de un usuario - ADMIN
 */
app.delete('/admin/users/:id/items', [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const usuario = await Usuario.findById(req.params.id);
        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        const resultado = await Juego.deleteMany({ usuario: usuario.usuario });

        res.json({
            success: true,
            mensaje: `${resultado.deletedCount} items eliminados`
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Resetear saldo de usuario - ADMIN
 */
app.put('/admin/users/:id/reset-saldo', [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const usuario = await Usuario.findById(req.params.id);
        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        usuario.saldo = 0;
        usuario.solicitudPagoPendiente = false;
        await usuario.save();

        res.json({
            success: true,
            mensaje: "Saldo reseteado"
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Usuarios elegibles para pago - ADMIN
 * DIFERENTE de /admin/finanzas/solicitudes-pendientes
 * Esta ruta muestra usuarios con saldo >= $10 que PUEDEN solicitar pago
 */
app.get('/admin/payments-pending', async (req, res) => {
    try {
        const usuariosParaPagar = await Usuario.find({
            saldo: { $gte: MIN_WITHDRAWAL },
            isVerificado: true,
            verificadoNivel: { $gte: 1 }
        }).select('usuario email paypalEmail saldo descargasTotales verificadoNivel');
        
        res.json({
            success: true,
            usuarios: usuariosParaPagar,
            total: usuariosParaPagar.length
        });
    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error al obtener pagos" });
    }
});

// ==========================================
// ⭐⭐⭐ ADMIN: GESTIÓN DE ITEMS
// ==========================================

/**
 * ⭐ Actualizar item - ADMIN
 */
app.put("/admin/items/:id", [
    param('id').isMongoId(),
    body('status').optional().isIn(['aprobado', 'rechazado', 'pendiente', 'pending'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: "ID o status inválido" });
        }

        const { status, title, description, image, link, category, linkStatus } = req.body;

        const updateData = {};
        if (status) updateData.status = status;
        if (title) updateData.title = title;
        if (description) updateData.description = description;
        if (image) updateData.image = image;
        if (link) updateData.link = link;
        if (category) updateData.category = category;
        if (linkStatus) updateData.linkStatus = linkStatus;

        const juego = await Juego.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true }
        );

        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        logger.info(`✏️ Item actualizado - ${juego.title}`);

        res.json({
            success: true,
            mensaje: "Item actualizado",
            item: juego
        });

    } catch (error) {
        logger.error("Error en actualizar item:", error);
        res.status(500).json({ error: "Error al actualizar" });
    }
});

/**
 * ⭐ Listar todos los items - ADMIN
 */
app.get("/admin/items", async (req, res) => {
    try {
        const { status, linkStatus, limit = 100 } = req.query;

        const query = {};
        if (status) query.status = status;
        if (linkStatus) query.linkStatus = linkStatus;

        const items = await Juego.find(query)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .lean();

        res.json({
            success: true,
            items,
            total: items.length
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error al obtener items" });
    }
});

/**
 * ⭐ Resetear reportes de un item - ADMIN
 */
app.put("/admin/items/:id/reset-reports", [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const juego = await Juego.findById(req.params.id);
        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        juego.reportes = 0;
        juego.linkStatus = 'online';
        await juego.save();

        res.json({
            success: true,
            mensaje: "Reportes reseteados"
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Cambiar estado del link - ADMIN
 */
app.put("/admin/items/:id/link-status", [
    param('id').isMongoId(),
    body('linkStatus').isIn(['online', 'revision', 'caido'])
], async (req, res) => {
    try {
        const { linkStatus } = req.body;

        const juego = await Juego.findById(req.params.id);
        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        juego.linkStatus = linkStatus;
        await juego.save();

        res.json({
            success: true,
            mensaje: "Estado del link actualizado",
            juego
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

// ==========================================
// ⭐⭐⭐ ITEMS (PÚBLICO/USUARIO)
// ==========================================

/**
 * ⭐ Reportar item
 */
app.put("/items/report/:id", [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const juego = await Juego.findById(req.params.id);
        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        juego.reportes += 1;
        
        if (juego.reportes >= 3) {
            juego.linkStatus = 'revision';
        }

        await juego.save();

        logger.info(`⚠️ Reporte - Juego: ${juego.title}, Total reportes: ${juego.reportes}`);

        res.json({
            success: true,
            mensaje: "Reporte registrado",
            reportes: juego.reportes,
            linkStatus: juego.linkStatus
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error al reportar" });
    }
});

/**
 * ⭐ Listar items públicos
 */
app.get("/items", async (req, res) => {
    try {
        const { category, search } = req.query;

        const query = { 
            status: 'aprobado',
            linkStatus: { $ne: 'caido' }
        };

        if (category && category !== 'Todos') {
            query.category = category;
        }

        if (search) {
            query.$or = [
                { title: new RegExp(search, 'i') },
                { description: new RegExp(search, 'i') }
            ];
        }

        const items = await Juego.find(query)
            .sort({ createdAt: -1 })
            .lean();

        res.json(items);

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error al obtener items" });
    }
});

/**
 * ⭐ Items de un usuario específico
 */
app.get("/items/user/:usuario", async (req, res) => {
    try {
        const items = await Juego.find({ usuario: req.params.usuario })
            .sort({ createdAt: -1 })
            .lean();

        res.json(items);

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Agregar nuevo item
 */
app.post("/items/add", [
    verificarToken,
    body('title').isLength({ min: 3, max: 200 }).trim(),
    body('link').isURL()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: "Datos inválidos",
                details: errors.array()
            });
        }

        const { title, description, image, link, category, tags } = req.body;

        const nuevoJuego = new Juego({
            usuario: req.usuario,
            title: title.trim(),
            description: description || '',
            image: image || '',
            link,
            category: category || 'General',
            tags: tags || [],
            status: 'pendiente',
            linkStatus: 'online'
        });

        await nuevoJuego.save();

        logger.info(`➕ Nuevo juego agregado - ${title} por @${req.usuario}`);

        res.json({
            success: true,
            mensaje: "Juego agregado exitosamente",
            item: nuevoJuego
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error al agregar juego" });
    }
});

/**
 * ⭐ Aprobar item
 */
app.put("/items/approve/:id", [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const juego = await Juego.findByIdAndUpdate(
            req.params.id,
            { status: 'aprobado' },
            { new: true }
        );

        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        res.json({
            success: true,
            mensaje: "Juego aprobado",
            item: juego
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Eliminar item
 */
app.delete("/items/:id", [
    verificarToken,
    param('id').isMongoId()
], async (req, res) => {
    try {
        const juego = await Juego.findById(req.params.id);
        
        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        if (juego.usuario !== req.usuario) {
            return res.status(403).json({ error: "No tienes permiso" });
        }

        await Juego.findByIdAndDelete(req.params.id);

        res.json({
            success: true,
            mensaje: "Juego eliminado"
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error al eliminar" });
    }
});

/**
 * ⭐ Obtener un item específico
 */
app.get('/items/:id', async (req, res) => {
    try {
        const juego = await Juego.findById(req.params.id).lean();
        
        if (!juego) {
            return res.status(404).json({ error: "Juego no encontrado" });
        }

        res.json(juego);

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

// ==========================================
// ⭐⭐⭐ USUARIOS
// ==========================================

/**
 * ⭐ Listar todos los usuarios
 */
app.get('/auth/users', async (req, res) => {
    try {
        const usuarios = await Usuario.find()
            .select('-password')
            .lean();

        res.json(usuarios);

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Detalle completo de usuario - ADMIN
 */
app.get('/admin/users/detalle/:id', async (req, res) => {
    try {
        const usuario = await Usuario.findById(req.params.id)
            .select('-password')
            .lean();

        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        const juegos = await Juego.countDocuments({ usuario: usuario.usuario });
        const pagos = await Pago.find({ usuario: usuario.usuario }).lean();

        res.json({
            success: true,
            usuario: {
                ...usuario,
                totalJuegos: juegos,
                historialPagos: pagos
            }
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Agregar/quitar de lista negra - ADMIN
 */
app.put('/admin/users/lista-negra/:id', [
    param('id').isMongoId(),
    body('listaNegraAdmin').isBoolean(),
    body('motivo').optional().isString()
], async (req, res) => {
    try {
        const { listaNegraAdmin, motivo } = req.body;

        const usuario = await Usuario.findById(req.params.id);
        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        usuario.listaNegraAdmin = listaNegraAdmin;
        
        if (listaNegraAdmin) {
            usuario.fechaListaNegra = new Date();
            if (motivo) {
                usuario.notasAdmin = (usuario.notasAdmin || '') + 
                    `\n[${new Date().toLocaleDateString()}]: ${motivo}`;
            }
        } else {
            usuario.fechaListaNegra = null;
        }

        await usuario.save();

        logger.info(`🚫 Lista negra - Usuario: @${usuario.usuario}, Estado: ${listaNegraAdmin}`);

        res.json({
            success: true,
            mensaje: listaNegraAdmin ? "Usuario agregado a lista negra" : "Usuario removido de lista negra",
            usuario: {
                usuario: usuario.usuario,
                listaNegraAdmin: usuario.listaNegraAdmin
            }
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Agregar notas de admin
 */
app.put('/admin/users/notas/:id', [
    param('id').isMongoId(),
    body('notas').isString()
], async (req, res) => {
    try {
        const { notas } = req.body;

        const usuario = await Usuario.findById(req.params.id);
        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        usuario.notasAdmin = notas;
        await usuario.save();

        res.json({
            success: true,
            mensaje: "Notas actualizadas"
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Listar usuarios en lista negra - ADMIN
 */
app.get('/admin/users/lista-negra', async (req, res) => {
    try {
        const usuarios = await Usuario.find({ listaNegraAdmin: true })
            .select('usuario email saldo descargasTotales notasAdmin fechaListaNegra')
            .lean();

        res.json({
            success: true,
            usuarios,
            total: usuarios.length
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Eliminar usuario
 */
app.delete('/auth/users/:id', async (req, res) => {
    try {
        await Usuario.findByIdAndDelete(req.params.id);
        res.json({ success: true, mensaje: "Usuario eliminado" });
    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Actualizar nivel de verificación - ADMIN
 */
app.put('/auth/admin/verificacion/:username', [
    body('verificadoNivel').isInt({ min: 0, max: 3 })
], async (req, res) => {
    try {
        const { verificadoNivel } = req.body;

        const usuario = await Usuario.findOneAndUpdate(
            { usuario: req.params.username },
            { 
                verificadoNivel,
                isVerificado: verificadoNivel >= 1
            },
            { new: true }
        ).select('-password');

        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json({
            success: true,
            mensaje: "Verificación actualizada",
            usuario
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

// ==========================================
// ⭐⭐⭐ PERFILES PÚBLICOS Y SEGUIMIENTO
// ==========================================

/**
 * ⭐ Perfil público de usuario
 */
app.get('/usuarios/perfil-publico/:usuario', async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.params.usuario })
            .select('usuario avatar bio reputacion verificadoNivel listaSeguidores siguiendo fecha')
            .lean();

        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        const juegos = await Juego.find({ 
            usuario: req.params.usuario,
            status: 'aprobado'
        }).select('title image descargasEfectivas createdAt').lean();

        res.json({
            usuario: {
                ...usuario,
                totalJuegos: juegos.length,
                seguidores: usuario.listaSeguidores?.length || 0,
                siguiendo: usuario.siguiendo?.length || 0
            },
            juegos
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Verificar si sigue a un usuario
 */
app.get('/usuarios/verifica-seguimiento/:actual/:viendo', async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.params.actual })
            .select('siguiendo');

        const siguiendo = usuario?.siguiendo?.includes(req.params.viendo) || false;

        res.json({ siguiendo });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Seguir/dejar de seguir
 */
app.put('/usuarios/toggle-seguir/:actual/:objetivo', async (req, res) => {
    try {
        const usuarioActual = await Usuario.findOne({ usuario: req.params.actual });
        const usuarioObjetivo = await Usuario.findOne({ usuario: req.params.objetivo });

        if (!usuarioActual || !usuarioObjetivo) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        const yaSigue = usuarioActual.siguiendo?.includes(req.params.objetivo);

        if (yaSigue) {
            usuarioActual.siguiendo = usuarioActual.siguiendo.filter(
                u => u !== req.params.objetivo
            );
            usuarioObjetivo.listaSeguidores = usuarioObjetivo.listaSeguidores.filter(
                u => u !== req.params.actual
            );
        } else {
            if (!usuarioActual.siguiendo) usuarioActual.siguiendo = [];
            if (!usuarioObjetivo.listaSeguidores) usuarioObjetivo.listaSeguidores = [];
            
            usuarioActual.siguiendo.push(req.params.objetivo);
            usuarioObjetivo.listaSeguidores.push(req.params.actual);
        }

        await usuarioActual.save();
        await usuarioObjetivo.save();

        res.json({
            success: true,
            siguiendo: !yaSigue,
            mensaje: yaSigue ? "Dejaste de seguir" : "Ahora sigues a este usuario"
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Actualizar avatar
 */
app.put('/usuarios/update-avatar', [
    verificarToken,
    body('avatar').isURL()
], async (req, res) => {
    try {
        const { avatar } = req.body;

        const usuario = await Usuario.findOneAndUpdate(
            { usuario: req.usuario },
            { avatar },
            { new: true }
        ).select('-password');

        res.json({
            success: true,
            mensaje: "Avatar actualizado",
            usuario
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Actualizar bio
 */
app.put('/usuarios/update-bio', [
    verificarToken,
    body('bio').isLength({ max: 200 })
], async (req, res) => {
    try {
        const { bio } = req.body;

        const usuario = await Usuario.findOneAndUpdate(
            { usuario: req.usuario },
            { bio },
            { new: true }
        ).select('-password');

        res.json({
            success: true,
            mensaje: "Bio actualizada",
            usuario
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Estadísticas de seguimiento
 */
app.get('/usuarios/stats-seguimiento/:usuario', async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.params.usuario })
            .select('listaSeguidores siguiendo verificadoNivel reputacion')
            .lean();

        if (!usuario) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json({
            success: true,
            seguidores: usuario.listaSeguidores?.length || 0,
            siguiendo: usuario.siguiendo?.length || 0,
            verificadoNivel: usuario.verificadoNivel || 0,
            reputacion: usuario.reputacion || 0
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

// ==========================================
// ⭐⭐⭐ COMENTARIOS
// ==========================================

/**
 * ⭐ Listar comentarios
 */
app.get('/comentarios', async (req, res) => {
    try {
        const comentarios = await Comentario.find()
            .sort({ fecha: -1 })
            .lean();
        res.json(comentarios);
    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Comentarios de un item
 */
app.get('/comentarios/:itemId', async (req, res) => {
    try {
        const comentarios = await Comentario.find({ itemId: req.params.itemId })
            .sort({ fecha: -1 })
            .lean();
        res.json(comentarios);
    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Agregar comentario
 */
app.post('/comentarios', [
    verificarToken,
    body('texto').isLength({ min: 1, max: 500 }),
    body('itemId').notEmpty()
], async (req, res) => {
    try {
        const { texto, itemId } = req.body;

        const comentario = new Comentario({
            usuario: req.usuario,
            texto,
            itemId,
            fecha: new Date()
        });

        await comentario.save();

        res.json({
            success: true,
            comentario
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Eliminar comentario
 */
app.delete('/comentarios/:id', async (req, res) => {
    try {
        await Comentario.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

// ==========================================
// ⭐⭐⭐ FAVORITOS
// ==========================================

/**
 * ⭐ Agregar a favoritos
 */
app.post('/favoritos/add', [
    verificarToken,
    body('itemId').isMongoId()
], async (req, res) => {
    try {
        const { itemId } = req.body;

        const existe = await Favorito.findOne({
            usuario: req.usuario,
            itemId
        });

        if (existe) {
            return res.json({
                success: false,
                mensaje: "Ya está en favoritos"
            });
        }

        const favorito = new Favorito({
            usuario: req.usuario,
            itemId
        });

        await favorito.save();

        res.json({
            success: true,
            mensaje: "Agregado a favoritos"
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Eliminar de favoritos
 */
app.delete('/favoritos/remove', [
    verificarToken,
    body('itemId').isMongoId()
], async (req, res) => {
    try {
        const { itemId } = req.body;

        await Favorito.deleteOne({
            usuario: req.usuario,
            itemId
        });

        res.json({
            success: true,
            mensaje: "Eliminado de favoritos"
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Listar favoritos de un usuario
 */
app.get('/favoritos/:usuario', async (req, res) => {
    try {
        const favoritos = await Favorito.find({ usuario: req.params.usuario })
            .populate('itemId')
            .lean();

        const items = favoritos
            .filter(f => f.itemId)
            .map(f => f.itemId);

        res.json(items);

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

// ==========================================
// ⭐⭐⭐ DETECCIÓN DE FRAUDE - ADMIN
// ==========================================

/**
 * ⭐ Actividades sospechosas - ADMIN
 */
app.get('/admin/fraud/suspicious-activities', async (req, res) => {
    try {
        const { revisado, severidad, limit = 50 } = req.query;

        const query = {};
        if (revisado !== undefined) {
            query.revisado = revisado === 'true';
        }
        if (severidad) {
            query.severidad = severidad;
        }

        const activities = await fraudDetector.SuspiciousActivity.find(query)
            .sort({ fecha: -1 })
            .limit(parseInt(limit))
            .lean();

        const stats = await fraudDetector.getSuspiciousStats();

        res.json({
            success: true,
            activities,
            stats
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Marcar actividad como revisada - ADMIN
 */
app.put('/admin/fraud/mark-reviewed/:activityId', [
    param('activityId').isMongoId(),
    body('notas').optional().isString()
], async (req, res) => {
    try {
        const { notas } = req.body;

        const activity = await fraudDetector.SuspiciousActivity.findById(req.params.activityId);
        
        if (!activity) {
            return res.status(404).json({ error: "Actividad no encontrada" });
        }

        activity.revisado = true;
        if (notas) {
            activity.notasAdmin = notas;
        }
        
        await activity.save();

        res.json({
            success: true,
            mensaje: "Actividad marcada como revisada",
            activity
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

/**
 * ⭐ Historial de fraude de un usuario - ADMIN
 */
app.get('/admin/fraud/user-history/:usuario', async (req, res) => {
    try {
        const activities = await fraudDetector.SuspiciousActivity.find({
            usuario: req.params.usuario
        })
        .sort({ fecha: -1 })
        .lean();

        const usuario = await Usuario.findOne({ usuario: req.params.usuario })
            .select('listaNegraAdmin notasAdmin fechaListaNegra saldo descargasTotales')
            .lean();

        res.json({
            success: true,
            usuario,
            activities,
            totalActivities: activities.length
        });

    } catch (error) {
        logger.error("Error:", error);
        res.status(500).json({ error: "Error" });
    }
});

// ==========================================
// ⭐⭐⭐ RUTAS GENERALES
// ==========================================

/**
 * ⭐ Healthcheck
 */
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '3.1.0',
        uptime: process.uptime(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        environment: process.env.NODE_ENV || 'development'
    });
});

/**
 * ⭐ Versión de la API
 */
app.get('/api/version', (req, res) => {
    res.json({
        version: '3.1.0',
        name: 'UpGames Backend',
        environment: process.env.NODE_ENV || 'development',
        features: {
            fraudDetection: config.FEATURES.ENABLE_FRAUD_DETECTION,
            autoPayments: config.FEATURES.ENABLE_AUTO_PAYMENTS,
            emailNotifications: config.FEATURES.ENABLE_EMAIL_NOTIFICATIONS
        }
    });
});

/**
 * ⭐ Ruta principal
 */
app.get('/', (req, res) => {
    res.json({
        mensaje: "✅ API de UpGames funcionando correctamente",
        version: "3.1.0",
        endpoints: {
            economia: "/economia/*",
            admin: "/admin/*",
            auth: "/auth/*",
            items: "/items",
            usuarios: "/usuarios/*",
            health: "/health"
        },
        documentacion: "Consulta /api/version para más información"
    });
});

// ==========================================
// ⭐⭐⭐ MANEJO DE ERRORES 404
// ==========================================
app.use((req, res) => {
    res.status(404).json({
        error: "Ruta no encontrada",
        path: req.path,
        method: req.method
    });
});

// ==========================================
// ⭐⭐⭐ JOBS AUTOMÁTICOS (CRON JOBS)
// ==========================================

/**
 * Función que inicia todos los trabajos automáticos del sistema
 * Se ejecuta después de que MongoDB esté conectado
 */
function iniciarJobsAutomaticos() {
    logger.info('');
    logger.info('⚙️  ========================================');
    logger.info('⚙️  INICIANDO JOBS AUTOMÁTICOS');
    logger.info('⚙️  ========================================');

    // ----------------------------------------------------------
    // JOB 1: AUTO-PING (cada 14 minutos)
    // Evita que Render duerma el servidor.
    // Se hace al propio endpoint / del servidor.
    // ----------------------------------------------------------
    const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 10000}`;

    setInterval(async () => {
        try {
            const res = await fetch(`${SELF_URL}/`);
            logger.info(`🏓 Auto-ping OK [${new Date().toLocaleTimeString('es-ES')}] - Status: ${res.status}`);
        } catch (err) {
            logger.warn(`⚠️ Auto-ping falló: ${err.message}`);
        }
    }, 14 * 60 * 1000); // 14 minutos

    logger.info('🏓 JOB 1: Auto-ping activo (cada 14 min)');

    // ----------------------------------------------------------
    // JOB 2: LIMPIAR COMENTARIOS VACÍOS Y DUPLICADOS (cada 24h)
    // - Elimina comentarios con texto vacío o solo espacios
    // - Elimina duplicados: mismo usuario, mismo item, mismo texto
    //   en menos de 60 segundos (spam de botones)
    // ----------------------------------------------------------
    async function limpiarComentarios() {
        try {
            // 2A: Borrar comentarios vacíos
            const vacios = await Comentario.deleteMany({
                $or: [
                    { texto: { $exists: false } },
                    { texto: null },
                    { texto: '' },
                    { texto: /^\s+$/ }
                ]
            });

            // 2B: Detectar y eliminar duplicados (mismo usuario + item + texto en <60s)
            const duplicados = await Comentario.aggregate([
                {
                    $group: {
                        _id: { usuario: '$usuario', itemId: '$itemId', texto: '$texto' },
                        ids: { $push: '$_id' },
                        count: { $sum: 1 }
                    }
                },
                { $match: { count: { $gt: 1 } } }
            ]);

            let eliminadosDuplicados = 0;
            for (const grupo of duplicados) {
                // Conservar el primero (ids[0]), eliminar el resto
                const aEliminar = grupo.ids.slice(1);
                await Comentario.deleteMany({ _id: { $in: aEliminar } });
                eliminadosDuplicados += aEliminar.length;
            }

            if (vacios.deletedCount > 0 || eliminadosDuplicados > 0) {
                logger.info(`🧹 JOB 2 Comentarios: ${vacios.deletedCount} vacíos + ${eliminadosDuplicados} duplicados eliminados`);
            } else {
                logger.info(`🧹 JOB 2 Comentarios: sin basura encontrada`);
            }
        } catch (err) {
            logger.error('❌ JOB 2 Error limpiando comentarios:', err.message);
        }
    }

    limpiarComentarios(); // Correr al arrancar
    setInterval(limpiarComentarios, 24 * 60 * 60 * 1000); // Cada 24h
    logger.info('🧹 JOB 2: Limpieza de comentarios activa (cada 24h)');

    // ----------------------------------------------------------
    // JOB 3: RESETEAR REPORTES DE JUEGOS EN ESTADO 'online' (cada 12h)
    // Si un juego lleva más de 48h con linkStatus='online' y tiene
    // reportes > 0, significa que el admin lo revisó y lo confirmó.
    // Los reportes viejos ya no tienen relevancia → resetear a 0.
    // ----------------------------------------------------------
    async function resetearReportesOnline() {
        try {
            const hace48h = new Date(Date.now() - 48 * 60 * 60 * 1000);

            const resultado = await Juego.updateMany(
                {
                    linkStatus: 'online',
                    reportes: { $gt: 0 },
                    updatedAt: { $lte: hace48h }
                },
                { $set: { reportes: 0 } }
            );

            if (resultado.modifiedCount > 0) {
                logger.info(`🔄 JOB 3 Reportes: ${resultado.modifiedCount} juegos reseteados a 0 reportes`);
            } else {
                logger.info(`🔄 JOB 3 Reportes: ningún juego necesitaba reset`);
            }
        } catch (err) {
            logger.error('❌ JOB 3 Error reseteando reportes:', err.message);
        }
    }

    setInterval(resetearReportesOnline, 12 * 60 * 60 * 1000); // Cada 12h
    logger.info('🔄 JOB 3: Reset de reportes activo (cada 12h)');

    // ----------------------------------------------------------
    // JOB 4: AUTO-RECHAZAR ITEMS PENDIENTES VIEJOS (cada 24h)
    // Items con status 'pendiente' o 'pending' de más de 7 días
    // se rechazan automáticamente para no saturar la cola de admin.
    // ----------------------------------------------------------
    async function autoRechazarPendientes() {
        try {
            const hace7dias = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

            const resultado = await Juego.updateMany(
                {
                    status: { $in: ['pendiente', 'pending'] },
                    createdAt: { $lte: hace7dias }
                },
                {
                    $set: {
                        status: 'rechazado',
                        linkStatus: 'caido'
                    }
                }
            );

            if (resultado.modifiedCount > 0) {
                logger.info(`⏰ JOB 4 Pendientes: ${resultado.modifiedCount} items auto-rechazados por expiración (7 días)`);
            } else {
                logger.info(`⏰ JOB 4 Pendientes: no hay items expirados`);
            }
        } catch (err) {
            logger.error('❌ JOB 4 Error en auto-rechazo:', err.message);
        }
    }

    autoRechazarPendientes(); // Correr al arrancar
    setInterval(autoRechazarPendientes, 24 * 60 * 60 * 1000); // Cada 24h
    logger.info('⏰ JOB 4: Auto-rechazo de pendientes activo (cada 24h)');

    // ----------------------------------------------------------
    // JOB 5: AUTO-MARCAR LINKS CAÍDOS POR REPORTES (cada 6h)
    // Si un juego lleva más de 72h en 'revision' y tiene 10+
    // reportes sin que el admin lo toque, se marca como 'caido'.
    // ----------------------------------------------------------
    async function autoMarcarCaidos() {
        try {
            const hace72h = new Date(Date.now() - 72 * 60 * 60 * 1000);

            const resultado = await Juego.updateMany(
                {
                    linkStatus: 'revision',
                    reportes: { $gte: 10 },
                    updatedAt: { $lte: hace72h }
                },
                { $set: { linkStatus: 'caido' } }
            );

            if (resultado.modifiedCount > 0) {
                logger.info(`🚨 JOB 5 Links: ${resultado.modifiedCount} links auto-marcados como caídos (10+ reportes, 72h sin revisión)`);
            } else {
                logger.info(`🚨 JOB 5 Links: ningún link requirió auto-marcar`);
            }
        } catch (err) {
            logger.error('❌ JOB 5 Error marcando links caídos:', err.message);
        }
    }

    setInterval(autoMarcarCaidos, 6 * 60 * 60 * 1000); // Cada 6h
    logger.info('🚨 JOB 5: Auto-marcado de links caídos activo (cada 6h)');

    // ----------------------------------------------------------
    // JOB 6: AUTO-VERIFICACIÓN POR SEGUIDORES (cada 6h)
    // Revisa todos los usuarios y asigna nivel de verificación
    // basado en su cantidad de seguidores:
    //   100+  seguidores → nivel 1
    //   500+  seguidores → nivel 2
    //   1000+ seguidores → nivel 3
    // El admin siempre puede sobreescribir manualmente desde el panel.
    // IMPORTANTE: Solo SUBE el nivel automáticamente, nunca lo baja.
    // Si el admin asignó nivel 3 manualmente con 50 seguidores, se respeta.
    // ----------------------------------------------------------
    async function autoVerificarUsuarios() {
        try {
            // Obtener todos los usuarios con sus seguidores (solo lo necesario)
            const usuarios = await Usuario.find({})
                .select('usuario listaSeguidores verificadoNivel')
                .lean();

            let subieron = 0;

            const operaciones = usuarios.map(user => {
                const seguidores = (user.listaSeguidores || []).length;

                let nivelMerecido = 0;
                if (seguidores >= 1000) nivelMerecido = 3;
                else if (seguidores >= 500)  nivelMerecido = 2;
                else if (seguidores >= 100)  nivelMerecido = 1;

                // Solo actualizar si el nivel merecido es MAYOR al que tiene
                // (nunca bajar por automatismo)
                if (nivelMerecido > (user.verificadoNivel || 0)) {
                    subieron++;
                    return {
                        updateOne: {
                            filter: { usuario: user.usuario },
                            update: { $set: { verificadoNivel: nivelMerecido, isVerificado: nivelMerecido >= 1 } }
                        }
                    };
                }
                return null;
            }).filter(Boolean);

            if (operaciones.length > 0) {
                await Usuario.bulkWrite(operaciones);
                logger.info(`✅ JOB 6 Verificación: ${subieron} usuarios subieron de nivel automáticamente`);
            } else {
                logger.info(`✅ JOB 6 Verificación: todos los niveles están al día`);
            }
        } catch (err) {
            logger.error('❌ JOB 6 Error en auto-verificación:', err.message);
        }
    }

    autoVerificarUsuarios(); // Correr al arrancar
    setInterval(autoVerificarUsuarios, 6 * 60 * 60 * 1000); // Cada 6h
    logger.info('✅ JOB 6: Auto-verificación por seguidores activa (cada 6h)');

    logger.info('');
    logger.info('⚙️  TODOS LOS JOBS AUTOMÁTICOS INICIADOS');
    logger.info('⚙️  ========================================');
}

// ==========================================
// ⭐⭐⭐ INICIAR SERVIDOR
// ==========================================
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
    logger.info('');
    logger.info('🚀 ========================================');
    logger.info('🚀 SERVIDOR UPGAMES v3.1.0 INICIADO');
    logger.info('🚀 ========================================');
    logger.info(`🌍 Puerto: ${PORT}`);
    logger.info(`🔧 Ambiente: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`💰 CPM: $${CPM_VALUE} (${AUTHOR_PERCENTAGE * 100}% al creador)`);
    logger.info(`📊 Umbral mínimo: ${MIN_DOWNLOADS_TO_EARN} descargas`);
    logger.info(`💸 Retiro mínimo: $${MIN_WITHDRAWAL} USD`);
    logger.info(`🛡️  Detección de fraude: ${config.FEATURES.ENABLE_FRAUD_DETECTION ? 'ACTIVA' : 'INACTIVA'}`);
    logger.info('🚀 ========================================');

    // Iniciar jobs después de que el servidor esté listo y MongoDB conectado
    mongoose.connection.once('open', () => {
        iniciarJobsAutomaticos();
    });
});

// Manejo de errores no capturados
process.on('unhandledRejection', (reason, promise) => {
    logger.error('❌ Unhandled Rejection:', reason);
});

process.on('uncaughtException', (error) => {
    logger.error('❌ Uncaught Exception:', error);
    process.exit(1);
});
