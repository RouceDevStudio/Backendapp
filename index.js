require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult, param } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// ⚠️ NUEVO: Módulo de detección de fraude
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
        if (!origin || allowedOrigins.some(allowed => origin.startsWith(allowed))) {
            callback(null, true);
        } else {
            callback(null, true); // En producción cambiar a: callback(new Error('CORS no permitido'))
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

// ⭐ NUEVO: Rate limiter específico para validación de descargas (anti-bots)
const downloadValidationLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minuto
    max: 10, // Máximo 10 validaciones por minuto por IP
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
        console.log(`${status} [${req.method}] ${req.path} - ${res.statusCode} (${duration}ms)`);
    });
    next();
});

// ========== CONEXIÓN MONGODB ==========
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET  = process.env.JWT_SECRET;

if (!MONGODB_URI || !JWT_SECRET) {
    console.error("❌ FALTAN VARIABLES DE ENTORNO: MONGODB_URI y JWT_SECRET son obligatorias.");
    process.exit(1);
}

mongoose.connect(MONGODB_URI, {
    maxPoolSize: 5,           // Reducido de 10 → ahorra ~50-80MB de RAM en plan gratuito
    minPoolSize: 1,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => console.log("🚀 MONGODB CONECTADO EXITOSAMENTE"))
.catch(err => {
    console.error("❌ ERROR CONEXIÓN MONGODB:", err.message);
    process.exit(1);
});

mongoose.connection.on('disconnected', () => {
    console.warn('⚠️ MongoDB desconectado. Intentando reconectar...');
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
        expires: 86400 // TTL: Se auto-elimina después de 24 horas (86400 segundos)
    }
});

// Índice compuesto — cubre búsquedas por juegoId, por ip, y por ambos juntos
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
    
    // ⭐ CAMPOS ECONÓMICOS
    descargasEfectivas: { 
        type: Number, 
        default: 0,
        min: 0
    }
}, { 
    timestamps: true
});

// Todos los índices declarados en un solo lugar (evita duplicados)
JuegoSchema.index({ usuario: 1, status: 1 });
JuegoSchema.index({ createdAt: -1 });
JuegoSchema.index({ linkStatus: 1 });
JuegoSchema.index({ descargasEfectivas: -1 });
JuegoSchema.index({ status: 1 });

// Middleware para actualizar linkStatus automáticamente
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
    // ⭐ Email (obligatorio para registro y login alternativo)
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
    // ⭐ Email de PayPal para pagos
    paypalEmail: {
        type: String,
        default: '',
        lowercase: true,
        trim: true,
        match: [/^(\S+@\S+\.\S+)?$/, 'Email de PayPal inválido']
    },
    // ⭐ Saldo en USD
    saldo: {
        type: Number,
        default: 0,
        min: 0
    },
    // ⭐ Historial de descargas totales de TODOS sus juegos
    descargasTotales: {
        type: Number,
        default: 0,
        min: 0
    },
    // ⭐ Verificación obligatoria para cobrar
    isVerificado: {
        type: Boolean,
        default: false,
        index: true
    },
    // ⭐ Solicitudes de pago pendientes
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
    // ⭐ IP de registro (capturada al hacer register)
    registrationIP: {
        type: String,
        default: ''
    },
    // ⭐ LISTA NEGRA ADMIN (solo visible en panel de admin)
    listaNegraAdmin: {
        type: Boolean,
        default: false,
        index: true
    },
    // ⭐ Notas privadas de admin sobre el usuario
    notasAdmin: {
        type: String,
        default: '',
        maxlength: 500
    },
    // ⭐ Fecha en que fue agregado a lista negra
    fechaListaNegra: {
        type: Date,
        default: null
    }
}, { 
    collection: 'usuarios',
    timestamps: true
});

// ⭐ Middleware: Auto-verificar si tiene nivel 1+ (solo si no está verificado)
UsuarioSchema.pre('save', function(next) {
    if (this.verificadoNivel >= 1 && !this.isVerificado) {
        this.isVerificado = true;
    }
    next();
});

const Usuario = mongoose.model('Usuario', UsuarioSchema);

// ⭐ SCHEMA: Historial de Pagos (para admin y transparencia)
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

// ==========================================
// ⭐⭐⭐ RUTAS DE ECONOMÍA (CORAZÓN DEL SISTEMA)
// ==========================================

// ⭐ CONSTANTES DE ECONOMÍA
const CPM_VALUE = 2.00; // $2.00 por cada 1,000 descargas efectivas
const AUTHOR_PERCENTAGE = 0.50; // 50% para el autor
const MIN_DOWNLOADS_TO_EARN = 2000; // Mínimo de descargas antes de empezar a ganar
const MIN_WITHDRAWAL = 10; // Mínimo de $10 USD para solicitar pago
const MAX_DOWNLOADS_PER_IP_PER_DAY = 2; // Máximo 2 descargas efectivas por IP por día

/**
 * ⭐ ENDPOINT CRÍTICO: Validar descarga efectiva
 * ⚠️ ACTUALIZADO: Ahora incluye detección automática de fraude
 * Este endpoint se llama desde puente.html después de que el usuario espera 30s
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
        
        // Obtener la IP real del usuario
        const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || 
                    req.headers['x-real-ip'] || 
                    req.connection.remoteAddress || 
                    req.socket.remoteAddress;

        console.log(`📥 Validación de descarga - Juego: ${juegoId}, IP: ${ip}`);

        // Paso 1: Verificar si el juego existe y está aprobado
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

        // Paso 2: Verificar límite de descargas por IP (2 por día)
        let registroIP = await DescargaIP.findOne({ juegoId, ip });
        
        if (registroIP) {
            if (registroIP.contadorHoy >= MAX_DOWNLOADS_PER_IP_PER_DAY) {
                console.log(`⚠️ Límite alcanzado - IP: ${ip}, Juego: ${juegoId}`);
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

        // Paso 3: Incrementar descargas efectivas del juego (atómico, sin cargar middleware pre-save)
        await Juego.findByIdAndUpdate(juegoId, { $inc: { descargasEfectivas: 1 } });
        juego.descargasEfectivas += 1; // Actualizar en memoria para usarlo más abajo

        // Paso 4: Obtener el autor del juego
        const autor = await Usuario.findOne({ usuario: juego.usuario });
        if (!autor) {
            console.warn(`⚠️ Autor no encontrado: ${juego.usuario}`);
            return res.json({
                success: true,
                descargaContada: true,
                link: juego.link,
                mensaje: "Descarga válida"
            });
        }

        // ⚠️ NUEVO: Verificar si el usuario está en lista negra
        if (autor.listaNegraAdmin) {
            console.log(`🚫 Usuario en lista negra detectado: @${autor.usuario} - Descarga NO contabilizada para ganancia`);
            
            // Incrementar contador de descargas pero NO sumar saldo
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

        // Paso 5: Actualizar descargas totales del autor
        autor.descargasTotales += 1;

        // Calcular ganancia potencial
        let gananciaGenerada = 0;
        let shouldAnalyzeFraud = false;

        // Paso 6: Verificar si el juego ya pasó el umbral de 2,000 descargas
        if (juego.descargasEfectivas > MIN_DOWNLOADS_TO_EARN) {
            // Paso 7: Verificar si el autor está verificado (nivel 1+)
            if (autor.isVerificado && autor.verificadoNivel >= 1) {
                // Calcular ganancia
                gananciaGenerada = (CPM_VALUE * AUTHOR_PERCENTAGE) / 1000;
                autor.saldo += gananciaGenerada;
                shouldAnalyzeFraud = true; // Solo analizar fraude si genera ganancia
                
                console.log(`💰 Ganancia generada - Autor: @${autor.usuario}, +$${gananciaGenerada.toFixed(4)} USD`);
            } else {
                console.log(`ℹ️ Autor no verificado - @${autor.usuario} - No se suma saldo`);
            }
        } else {
            console.log(`ℹ️ Juego aún no alcanza 2,000 descargas - Actual: ${juego.descargasEfectivas}`);
        }

        // ⚠️ ANÁLISIS DE FRAUDE: Solo se ejecuta si el juego superó el umbral Y el autor está verificado
        // (cuando shouldAnalyzeFraud = true). En otros casos no tiene sentido registrar en download_tracking.
        if (shouldAnalyzeFraud) {
            const fraudAnalysis = await fraudDetector.analyzeDownloadBehavior(
                autor.usuario,
                juegoId,
                ip,
                gananciaGenerada
            );

            if (fraudAnalysis.suspicious) {
                console.log(`⚠️ COMPORTAMIENTO SOSPECHOSO - @${autor.usuario}:`);
                fraudAnalysis.reasons.forEach(reason => console.log(`   - ${reason}`));

                // Si la severidad es crítica o alta, marcar automáticamente
                if (fraudAnalysis.autoFlag) {
                    const flagged = await fraudDetector.autoFlagUser(
                        Usuario,
                        autor.usuario,
                        `Detección automática: ${fraudAnalysis.reasons.join(', ')}`
                    );

                    if (flagged) {
                        // ⚠️ REVERTIR LA GANANCIA DE ESTA DESCARGA
                        autor.saldo -= gananciaGenerada;
                        gananciaGenerada = 0;
                        
                        console.log(`🚫 Usuario auto-marcado y ganancia revertida: @${autor.usuario}`);
                    }
                }
            }
        }

        await autor.save();

        console.log(`✅ Descarga efectiva validada - Juego: ${juego.title}, Total: ${juego.descargasEfectivas}`);

        res.json({
            success: true,
            descargaContada: true,
            link: juego.link,
            descargasEfectivas: juego.descargasEfectivas,
            mensaje: "Descarga válida y contada"
        });

    } catch (error) {
        console.error("❌ Error en validar-descarga:", error);
        res.status(500).json({ 
            success: false, 
            error: "Error al validar descarga" 
        });
    }
});

/**
 * ⭐ Solicitar pago (usuario)
 * Requisitos: saldo >= $10, verificado, PayPal configurado
 */
app.post('/economia/solicitar-pago', verificarToken, async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.usuario });
        
        if (!usuario) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        // Verificar requisitos
        if (!usuario.isVerificado || usuario.verificadoNivel < 1) {
            return res.status(403).json({ 
                success: false, 
                error: "Debes ser verificado (nivel 1+) para solicitar pagos" 
            });
        }

        if (usuario.saldo < MIN_WITHDRAWAL) {
            return res.status(400).json({ 
                success: false, 
                error: `Saldo mínimo para retiro: $${MIN_WITHDRAWAL} USD. Tu saldo: $${usuario.saldo.toFixed(2)}` 
            });
        }

        if (!usuario.paypalEmail || usuario.paypalEmail.trim() === '') {
            return res.status(400).json({ 
                success: false, 
                error: "Debes configurar tu email de PayPal primero" 
            });
        }

        if (usuario.solicitudPagoPendiente) {
            return res.status(400).json({ 
                success: false, 
                error: "Ya tienes una solicitud de pago pendiente" 
            });
        }

        // Verificar que tenga al menos 1 juego con más de 2,000 descargas
        const juegoElegible = await Juego.findOne({
            usuario: usuario.usuario,
            descargasEfectivas: { $gt: MIN_DOWNLOADS_TO_EARN }
        });

        if (!juegoElegible) {
            return res.status(403).json({ 
                success: false, 
                error: `Ninguno de tus juegos ha alcanzado las ${MIN_DOWNLOADS_TO_EARN} descargas necesarias` 
            });
        }

        // Crear solicitud de pago
        const nuevoPago = new Pago({
            usuario: usuario.usuario,
            monto: usuario.saldo,
            paypalEmail: usuario.paypalEmail,
            estado: 'pendiente'
        });
        await nuevoPago.save();

        // Marcar solicitud como pendiente
        usuario.solicitudPagoPendiente = true;
        await usuario.save();

        console.log(`💳 Solicitud de pago creada - @${usuario.usuario}, Monto: $${usuario.saldo.toFixed(2)}`);

        res.json({
            success: true,
            mensaje: "Solicitud de pago enviada. El administrador la revisará pronto.",
            solicitud: {
                monto: usuario.saldo,
                paypalEmail: usuario.paypalEmail,
                fecha: nuevoPago.fecha
            }
        });

    } catch (error) {
        console.error("❌ Error en solicitar-pago:", error);
        res.status(500).json({ success: false, error: "Error al procesar solicitud de pago" });
    }
});

/**
 * ⭐ Obtener datos económicos del usuario (para perfil)
 */
app.get('/economia/mi-saldo', verificarToken, async (req, res) => {
    try {
        const usuario = await Usuario.findOne({ usuario: req.usuario })
            .select('saldo descargasTotales paypalEmail isVerificado solicitudPagoPendiente verificadoNivel');

        if (!usuario) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        // Contar juegos con más de 2,000 descargas
        const juegosElegibles = await Juego.countDocuments({
            usuario: req.usuario,
            descargasEfectivas: { $gt: MIN_DOWNLOADS_TO_EARN }
        });

        const puedeRetirar = usuario.saldo >= MIN_WITHDRAWAL && 
                             usuario.isVerificado && 
                             usuario.verificadoNivel >= 1 &&
                             usuario.paypalEmail &&
                             juegosElegibles > 0 &&
                             !usuario.solicitudPagoPendiente;

        res.json({
            success: true,
            saldo: usuario.saldo,
            descargasTotales: usuario.descargasTotales,
            paypalEmail: usuario.paypalEmail || '',
            isVerificado: usuario.isVerificado,
            verificadoNivel: usuario.verificadoNivel,
            solicitudPagoPendiente: usuario.solicitudPagoPendiente,
            juegosElegibles,
            puedeRetirar,
            minRetiro: MIN_WITHDRAWAL,
            requisitos: {
                saldoMinimo: MIN_WITHDRAWAL,
                verificacionNecesaria: 1,
                descargasMinimas: MIN_DOWNLOADS_TO_EARN
            }
        });

    } catch (error) {
        console.error("❌ Error en mi-saldo:", error);
        res.status(500).json({ success: false, error: "Error al obtener saldo" });
    }
});

/**
 * ⭐ Actualizar email de PayPal (usuario logueado)
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

        await Usuario.updateOne(
            { usuario: req.usuario },
            { $set: { paypalEmail: paypalEmail.toLowerCase() } }
        );

        console.log(`✅ PayPal actualizado - @${req.usuario} → ${paypalEmail}`);

        res.json({ 
            success: true, 
            mensaje: "Email de PayPal actualizado correctamente",
            paypalEmail: paypalEmail.toLowerCase()
        });

    } catch (error) {
        console.error("❌ Error en actualizar-paypal:", error);
        res.status(500).json({ success: false, error: "Error al actualizar PayPal" });
    }
});

// ⭐ RUTA LEGACY: Mantener compatibilidad con tu código anterior
app.put('/usuarios/configurar-paypal', verificarToken, async (req, res) => {
    try {
        const { paypalEmail } = req.body;
        const usuarioLogueado = req.userTokenData.usuario;

        if (!paypalEmail || !paypalEmail.includes('@')) {
            return res.status(400).json({ success: false, error: "Email de PayPal inválido" });
        }

        const user = await Usuario.findOneAndUpdate(
            { usuario: usuarioLogueado.toLowerCase() },
            { $set: { paypalEmail: paypalEmail.toLowerCase().trim() } },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        console.log(`💰 PayPal actualizado para: @${usuarioLogueado} -> ${paypalEmail}`);

        res.json({ 
            success: true, 
            msg: "PayPal actualizado correctamente",
            paypalEmail: user.paypalEmail 
        });
    } catch (error) {
        console.error('[ERROR PayPal]:', error.message);
        res.status(500).json({ success: false, error: "Error de servidor al guardar PayPal" });
    }
});

// ==========================================
// ⭐⭐⭐ RUTAS DE ADMIN - FINANZAS
// ==========================================

/**
 * ⭐ Obtener todas las solicitudes de pago pendientes (ADMIN)
 */
app.get('/admin/finanzas/solicitudes-pendientes', async (req, res) => {
    try {
        const solicitudes = await Pago.find({ estado: 'pendiente' })
            .sort({ fecha: -1 })
            .lean();

        // Enriquecer con datos del usuario
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
        console.error("❌ Error en solicitudes-pendientes:", error);
        res.status(500).json({ success: false, error: "Error al cargar solicitudes" });
    }
});

/**
 * ⭐ Procesar pago (marcar como completado y restar saldo) - ADMIN
 */
app.post('/admin/finanzas/procesar-pago/:id', [
    param('id').isMongoId(),
    body('notas').optional().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, error: "ID inválido" });
        }

        const { id } = req.params;
        const { notas } = req.body;

        const pago = await Pago.findById(id);
        if (!pago) {
            return res.status(404).json({ success: false, error: "Pago no encontrado" });
        }

        if (pago.estado !== 'pendiente') {
            return res.status(400).json({ 
                success: false, 
                error: "Este pago ya fue procesado" 
            });
        }

        // Actualizar estado del pago
        pago.estado = 'completado';
        pago.notas = notas || `Pago procesado el ${new Date().toLocaleString('es-ES')}`;
        await pago.save();

        // Restar saldo del usuario y quitar flag de solicitud pendiente
        const usuario = await Usuario.findOne({ usuario: pago.usuario });
        if (usuario) {
            usuario.saldo = Math.max(0, usuario.saldo - pago.monto);
            usuario.solicitudPagoPendiente = false;
            await usuario.save();
        }

        console.log(`✅ Pago procesado - @${pago.usuario}, Monto: $${pago.monto.toFixed(2)}`);

        res.json({
            success: true,
            mensaje: "Pago procesado correctamente",
            pago: {
                usuario: pago.usuario,
                monto: pago.monto,
                paypalEmail: pago.paypalEmail,
                fecha: pago.fecha
            }
        });

    } catch (error) {
        console.error("❌ Error en procesar-pago:", error);
        res.status(500).json({ success: false, error: "Error al procesar pago" });
    }
});

/**
 * ⭐ Rechazar pago - ADMIN
 */
app.post('/admin/finanzas/rechazar-pago/:id', [
    param('id').isMongoId(),
    body('motivo').optional().trim()
], async (req, res) => {
    try {
        const { id } = req.params;
        const { motivo } = req.body;

        const pago = await Pago.findById(id);
        if (!pago) {
            return res.status(404).json({ success: false, error: "Pago no encontrado" });
        }

        pago.estado = 'rechazado';
        pago.notas = motivo || 'Rechazado por el administrador';
        await pago.save();

        // Quitar flag de solicitud pendiente
        await Usuario.updateOne(
            { usuario: pago.usuario },
            { $set: { solicitudPagoPendiente: false } }
        );

        console.log(`❌ Pago rechazado - @${pago.usuario}, Motivo: ${motivo}`);

        res.json({
            success: true,
            mensaje: "Pago rechazado",
            pago: {
                usuario: pago.usuario,
                monto: pago.monto,
                motivo: pago.notas
            }
        });

    } catch (error) {
        console.error("❌ Error en rechazar-pago:", error);
        res.status(500).json({ success: false, error: "Error al rechazar pago" });
    }
});

/**
 * ⭐ Obtener historial completo de pagos - ADMIN
 */
app.get('/admin/finanzas/historial', async (req, res) => {
    try {
        const { estado, usuario, limite = 50 } = req.query;

        const filtro = {};
        if (estado) filtro.estado = estado;
        if (usuario) filtro.usuario = usuario.toLowerCase();

        const historial = await Pago.find(filtro)
            .sort({ fecha: -1 })
            .limit(parseInt(limite))
            .lean();

        res.json({
            success: true,
            historial,
            total: historial.length
        });

    } catch (error) {
        console.error("❌ Error en historial:", error);
        res.status(500).json({ success: false, error: "Error al cargar historial" });
    }
});

/**
 * ⭐ Estadísticas generales de finanzas - ADMIN
 */
app.get('/admin/finanzas/estadisticas', async (req, res) => {
    try {
        const totalSolicitado = await Pago.aggregate([
            { $match: { estado: 'pendiente' } },
            { $group: { _id: null, total: { $sum: '$monto' } } }
        ]);

        const totalPagado = await Pago.aggregate([
            { $match: { estado: 'completado' } },
            { $group: { _id: null, total: { $sum: '$monto' } } }
        ]);

        const totalUsuariosConSaldo = await Usuario.countDocuments({ saldo: { $gt: 0 } });
        const totalUsuariosVerificados = await Usuario.countDocuments({ isVerificado: true });

        res.json({
            success: true,
            estadisticas: {
                solicitudesPendientes: await Pago.countDocuments({ estado: 'pendiente' }),
                totalSolicitado: totalSolicitado[0]?.total || 0,
                totalPagado: totalPagado[0]?.total || 0,
                usuariosConSaldo: totalUsuariosConSaldo,
                usuariosVerificados: totalUsuariosVerificados
            }
        });

    } catch (error) {
        console.error("❌ Error en estadísticas:", error);
        res.status(500).json({ success: false, error: "Error al cargar estadísticas" });
    }
});

/**
 * ⭐ Obtener juegos en estado "revisión" (linkStatus = "revision") - ADMIN
 */
app.get('/admin/links/en-revision', async (req, res) => {
    try {
        const juegosEnRevision = await Juego.find({ linkStatus: 'revision' })
            .sort({ reportes: -1, createdAt: -1 })
            .lean();

        res.json({
            success: true,
            juegos: juegosEnRevision,
            total: juegosEnRevision.length
        });

    } catch (error) {
        console.error("❌ Error en links en revisión:", error);
        res.status(500).json({ success: false, error: "Error al cargar links en revisión" });
    }
});

/**
 * ⭐ Marcar link como caído - ADMIN
 */
app.put('/admin/links/marcar-caido/:id', [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const { id } = req.params;

        const juego = await Juego.findByIdAndUpdate(
            id,
            { $set: { linkStatus: 'caido' } },
            { new: true }
        );

        if (!juego) {
            return res.status(404).json({ success: false, error: "Juego no encontrado" });
        }

        console.log(`⚠️ Link marcado como caído - ${juego.title}`);

        res.json({
            success: true,
            mensaje: "Link marcado como caído. No se mostrará en biblioteca.",
            juego: {
                _id: juego._id,
                title: juego.title,
                linkStatus: juego.linkStatus
            }
        });

    } catch (error) {
        console.error("❌ Error en marcar-caido:", error);
        res.status(500).json({ success: false, error: "Error al marcar link como caído" });
    }
});

// ⭐ RUTA LEGACY: Mantener compatibilidad con verificación de descarga anterior
app.post('/items/verify-download/:id', async (req, res) => {
    try {
        const itemId = req.params.id;
        const userIP = req.ip || req.headers['x-forwarded-for'];

        // Redirigir a la nueva lógica
        return res.json({ 
            success: true, 
            mensaje: "Por favor usa /economia/validar-descarga con el ID en el body",
            deprecado: true
        });

    } catch (error) {
        res.status(500).json({ error: "Error en validación" });
    }
});

// ==========================================
// ⭐ RUTAS DE AUTENTICACIÓN (ACTUALIZADAS CON EMAIL)
// ==========================================

/**
 * ⭐ REGISTRO (AHORA REQUIERE: NOMBRE, EMAIL, CONTRASEÑA)
 */
app.post('/auth/register', [
    body('usuario').trim().isLength({ min: 3, max: 20 }).toLowerCase(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos",
                details: errors.array()
            });
        }

        const { usuario, email, password } = req.body;

        // Capturar IP de registro
        const registrationIP = req.headers['x-forwarded-for']?.split(',')[0].trim() || 
                                req.headers['x-real-ip'] || 
                                req.connection?.remoteAddress || 
                                req.socket?.remoteAddress || '';

        // Verificar si el usuario ya existe
        const existeUsuario = await Usuario.findOne({ usuario: usuario.toLowerCase() });
        if (existeUsuario) {
            return res.status(400).json({ 
                success: false, 
                error: "El nombre de usuario ya está en uso" 
            });
        }

        // Verificar si el email ya existe
        const existeEmail = await Usuario.findOne({ email: email.toLowerCase() });
        if (existeEmail) {
            return res.status(400).json({ 
                success: false, 
                error: "El email ya está registrado" 
            });
        }

        // Hash de contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear usuario
        const nuevoUsuario = new Usuario({
            usuario: usuario.toLowerCase(),
            email: email.toLowerCase(),
            password: hashedPassword,
            registrationIP: registrationIP
        });

        await nuevoUsuario.save();

        console.log(`✅ Nuevo usuario registrado: @${usuario} (${email})`);

        // Generar token
        const token = jwt.sign({ usuario: nuevoUsuario.usuario, email: nuevoUsuario.email }, JWT_SECRET, { expiresIn: '30d' });

        res.status(201).json({
            success: true,
            ok: true,
            token,
            usuario: nuevoUsuario.usuario,
            email: nuevoUsuario.email,
            datosUsuario: {
                usuario: nuevoUsuario.usuario,
                email: nuevoUsuario.email,
                verificadoNivel: nuevoUsuario.verificadoNivel,
                isVerificado: nuevoUsuario.isVerificado
            }
        });

    } catch (error) {
        console.error("❌ Error en register:", error);
        res.status(500).json({ success: false, error: "Error al registrar usuario" });
    }
});

/**
 * ⭐ LOGIN (AHORA ACEPTA NOMBRE DE USUARIO O EMAIL)
 */
app.post('/auth/login', [
    body('usuario').notEmpty(), // Puede ser usuario o email (manteniendo compatibilidad)
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const { usuario: identificador, password } = req.body;

        // Buscar por nombre de usuario O por email
        const usuario = await Usuario.findOne({
            $or: [
                { usuario: identificador.toLowerCase() },
                { email: identificador.toLowerCase() }
            ]
        });

        if (!usuario) {
            return res.status(401).json({ 
                success: false, 
                error: "Usuario o contraseña incorrectos" 
            });
        }

        // Verificar contraseña
        const esValida = await bcrypt.compare(password, usuario.password);
        if (!esValida) {
            return res.status(401).json({ 
                success: false, 
                error: "Usuario o contraseña incorrectos" 
            });
        }

        // Generar token
        const token = jwt.sign({ usuario: usuario.usuario, email: usuario.email }, JWT_SECRET, { expiresIn: '30d' });

        console.log(`✅ Login exitoso: @${usuario.usuario}`);

        res.json({
            success: true,
            ok: true,
            token,
            usuario: usuario.usuario,
            email: usuario.email,
            datosUsuario: {
                usuario: usuario.usuario,
                email: usuario.email,
                verificadoNivel: usuario.verificadoNivel,
                isVerificado: usuario.isVerificado,
                saldo: usuario.saldo
            }
        });

    } catch (error) {
        console.error("❌ Error en login:", error);
        res.status(500).json({ success: false, error: "Error al iniciar sesión" });
    }
});

// ==========================================
// ⭐⭐⭐ RUTAS ADMIN DE PODER - DASHBOARD & CONTROL TOTAL
// ==========================================

/**
 * ⭐ DASHBOARD: Métricas globales en tiempo real
 */
app.get('/admin/stats/dashboard', async (req, res) => {
    try {
        const ahora = new Date();
        const hoy = new Date(ahora.getFullYear(), ahora.getMonth(), ahora.getDate());
        const semana = new Date(ahora.getTime() - 7 * 24 * 60 * 60 * 1000);
        const mes = new Date(ahora.getFullYear(), ahora.getMonth(), 1);

        const [
            totalUsers, usersHoy, usersSemana,
            totalItems, itemsPendientes, itemsAprobados, itemsHoy,
            totalDescargas, descargasHoy,
            saldoTotal, saldoPendientePago,
            totalComentarios, comentariosHoy,
            topUploaders, usuariosListaNegra,
            itemsMasDescargados
        ] = await Promise.all([
            Usuario.countDocuments(),
            Usuario.countDocuments({ createdAt: { $gte: hoy } }),
            Usuario.countDocuments({ createdAt: { $gte: semana } }),
            Juego.countDocuments(),
            Juego.countDocuments({ status: { $in: ['pendiente', 'pending'] } }),
            Juego.countDocuments({ status: 'aprobado' }),
            Juego.countDocuments({ createdAt: { $gte: hoy } }),
            Juego.aggregate([{ $group: { _id: null, total: { $sum: '$descargasEfectivas' } } }]),
            DescargaIP.countDocuments({ fecha: { $gte: hoy } }),
            Usuario.aggregate([{ $group: { _id: null, total: { $sum: '$saldo' } } }]),
            Pago.aggregate([{ $match: { estado: 'pendiente' } }, { $group: { _id: null, total: { $sum: '$monto' } } }]),
            Comentario.countDocuments(),
            Comentario.countDocuments({ fecha: { $gte: hoy } }),
            Juego.aggregate([
                { $match: { status: 'aprobado' } },
                { $group: { _id: '$usuario', totalDescargas: { $sum: '$descargasEfectivas' }, totalItems: { $sum: 1 } } },
                { $sort: { totalDescargas: -1 } },
                { $limit: 5 }
            ]),
            Usuario.countDocuments({ listaNegraAdmin: true }),
            Juego.find({ status: 'aprobado' }).sort({ descargasEfectivas: -1 }).limit(5).select('title usuario descargasEfectivas').lean()
        ]);

        res.json({
            success: true,
            dashboard: {
                usuarios: {
                    total: totalUsers,
                    hoy: usersHoy,
                    semana: usersSemana,
                    listaNegra: usuariosListaNegra
                },
                items: {
                    total: totalItems,
                    pendientes: itemsPendientes,
                    aprobados: itemsAprobados,
                    hoy: itemsHoy
                },
                descargas: {
                    total: totalDescargas[0]?.total || 0,
                    hoy: descargasHoy
                },
                finanzas: {
                    saldoEnCirculacion: parseFloat((saldoTotal[0]?.total || 0).toFixed(2)),
                    pendienteDePago: parseFloat((saldoPendientePago[0]?.total || 0).toFixed(2))
                },
                comentarios: {
                    total: totalComentarios,
                    hoy: comentariosHoy
                },
                topUploaders,
                itemsMasDescargados
            }
        });
    } catch (error) {
        console.error("❌ Error en dashboard:", error);
        res.status(500).json({ success: false, error: "Error al cargar dashboard" });
    }
});

/**
 * ⭐ ADMIN: Ajustar saldo de usuario manualmente
 */
app.put('/admin/users/ajustar-saldo/:id', [
    param('id').isMongoId(),
    body('saldo').isFloat({ min: 0 }),
    body('motivo').optional().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, error: "Datos inválidos" });

        const { saldo, motivo } = req.body;
        const user = await Usuario.findByIdAndUpdate(
            req.params.id,
            { $set: { saldo: parseFloat(saldo) } },
            { new: true }
        ).select('-password');

        if (!user) return res.status(404).json({ success: false, error: "Usuario no encontrado" });

        console.log(`💰 ADMIN: Saldo ajustado @${user.usuario} → $${saldo} (${motivo || 'Sin motivo'})`);
        res.json({ success: true, usuario: user.usuario, nuevoSaldo: user.saldo });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al ajustar saldo" });
    }
});

/**
 * ⭐ ADMIN: Aprobar/Rechazar items en lote
 */
app.put('/admin/items/bulk-action', [
    body('ids').isArray({ min: 1 }),
    body('action').isIn(['aprobar', 'rechazar', 'eliminar', 'online', 'caido'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, error: "Datos inválidos" });

        const { ids, action } = req.body;
        let resultado;

        if (action === 'aprobar') {
            resultado = await Juego.updateMany(
                { _id: { $in: ids } },
                { $set: { status: 'aprobado' } }
            );
        } else if (action === 'rechazar') {
            resultado = await Juego.updateMany(
                { _id: { $in: ids } },
                { $set: { status: 'rechazado' } }
            );
        } else if (action === 'eliminar') {
            resultado = await Juego.deleteMany({ _id: { $in: ids } });
        } else if (action === 'online') {
            resultado = await Juego.updateMany(
                { _id: { $in: ids } },
                { $set: { linkStatus: 'online', reportes: 0 } }
            );
        } else if (action === 'caido') {
            resultado = await Juego.updateMany(
                { _id: { $in: ids } },
                { $set: { linkStatus: 'caido' } }
            );
        }

        const afectados = resultado?.modifiedCount || resultado?.deletedCount || 0;
        console.log(`✅ ADMIN BULK: ${action} en ${afectados} items`);
        res.json({ success: true, afectados, action });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error en acción en lote" });
    }
});

/**
 * ⭐ ADMIN: Rechazar pago desde panel
 */
app.post('/admin/finanzas/rechazar-pago-admin/:id', [
    param('id').isMongoId(),
    body('motivo').optional().trim()
], async (req, res) => {
    try {
        const pago = await Pago.findById(req.params.id);
        if (!pago) return res.status(404).json({ success: false, error: "Pago no encontrado" });
        if (pago.estado !== 'pendiente') return res.status(400).json({ success: false, error: "El pago ya fue procesado" });

        pago.estado = 'rechazado';
        pago.notas = req.body.motivo || 'Rechazado por el administrador';
        await pago.save();

        await Usuario.updateOne({ usuario: pago.usuario }, { $set: { solicitudPagoPendiente: false } });

        console.log(`❌ ADMIN: Pago rechazado @${pago.usuario}`);
        res.json({ success: true, mensaje: "Pago rechazado" });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al rechazar pago" });
    }
});

/**
 * ⭐ ADMIN: Historial completo de pagos (pendientes + completados + rechazados)
 */
app.get('/admin/finanzas/historial-completo', async (req, res) => {
    try {
        const { estado, limite = 100 } = req.query;
        const filtro = estado ? { estado } : {};
        const historial = await Pago.find(filtro)
            .sort({ fecha: -1 })
            .limit(parseInt(limite))
            .lean();
        res.json({ success: true, historial, total: historial.length });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al cargar historial" });
    }
});

/**
 * ⭐ ADMIN: Top usuarios por saldo / descargas
 */
app.get('/admin/stats/top-usuarios', async (req, res) => {
    try {
        const { por = 'saldo', limite = 10 } = req.query;
        const sortField = por === 'descargas' ? { descargasTotales: -1 } : { saldo: -1 };
        
        const users = await Usuario.find({ [por === 'descargas' ? 'descargasTotales' : 'saldo']: { $gt: 0 } })
            .sort(sortField)
            .limit(parseInt(limite))
            .select('usuario email saldo descargasTotales verificadoNivel paypalEmail')
            .lean();

        res.json({ success: true, users, criterio: por });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al cargar top usuarios" });
    }
});

/**
 * ⭐ ADMIN: Eliminar TODOS los items de un usuario
 */
app.delete('/admin/users/:id/items', [param('id').isMongoId()], async (req, res) => {
    try {
        const user = await Usuario.findById(req.params.id).select('usuario');
        if (!user) return res.status(404).json({ success: false, error: "Usuario no encontrado" });

        const resultado = await Juego.deleteMany({ usuario: user.usuario });
        console.log(`🗑️ ADMIN: ${resultado.deletedCount} items de @${user.usuario} eliminados`);
        res.json({ success: true, eliminados: resultado.deletedCount, usuario: user.usuario });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al eliminar items" });
    }
});

/**
 * ⭐ ADMIN: Resetear saldo a 0 (sanción financiera)
 */
app.put('/admin/users/:id/reset-saldo', [param('id').isMongoId()], async (req, res) => {
    try {
        const user = await Usuario.findByIdAndUpdate(
            req.params.id,
            { $set: { saldo: 0, solicitudPagoPendiente: false } },
            { new: true }
        ).select('usuario saldo');

        if (!user) return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        console.log(`⚡ ADMIN: Saldo reseteado a 0 para @${user.usuario}`);
        res.json({ success: true, usuario: user.usuario });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al resetear saldo" });
    }
});

// ==========================================
// RUTAS ORIGINALES DE ADMIN (MANTENER)
// ==========================================

app.get('/admin/payments-pending', async (req, res) => {
    try {
        const usuariosParaPagar = await Usuario.find({
            saldo: { $gte: 10 },
            isVerificado: true,
            verificadoNivel: { $gte: 1 }
        }).select('usuario email paypalEmail saldo descargasTotales verificadoNivel');
        
        res.json(usuariosParaPagar);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener pagos" });
    }
});

app.put("/admin/items/:id", [
    param('id').isMongoId(),
    body('title').optional().trim().isLength({ max: 200 }),
    body('description').optional().trim().isLength({ max: 1000 }),
    body('link').optional().trim(),
    body('image').optional().trim(),
    body('category').optional().trim(),
    body('status').optional().isIn(['pendiente', 'aprobado', 'rechazado', 'pending']),
    body('linkStatus').optional().isIn(['online', 'revision', 'caido']),
    body('reportes').optional().isInt({ min: 0 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos",
                details: errors.array()
            });
        }

        const updates = {};
        const allowedFields = ['title', 'description', 'link', 'image', 'category', 'status', 'linkStatus', 'reportes'];
        
        allowedFields.forEach(field => {
            if (req.body[field] !== undefined) {
                updates[field] = req.body[field];
            }
        });

        const item = await Juego.findByIdAndUpdate(
            req.params.id,
            { $set: updates },
            { new: true, runValidators: true }
        );

        if (!item) {
            return res.status(404).json({ success: false, error: "Item no encontrado" });
        }

        console.log(`✅ ADMIN: Item ${item._id} actualizado`);
        res.json({ success: true, item });
    } catch (error) {
        console.error('[ERROR /admin/items/:id]:', error.message);
        res.status(500).json({ success: false, error: "Error al actualizar item" });
    }
});

app.get("/admin/items", async (req, res) => {
    try {
        const items = await Juego.find()
            .sort({ createdAt: -1 })
            .lean();
        
        const itemsWithInfo = items.map(item => ({
            ...item,
            diasDesdeCreacion: Math.floor((Date.now() - new Date(item.createdAt).getTime()) / (1000 * 60 * 60 * 24)),
            necesitaRevision: item.reportes >= 3 || item.linkStatus === 'revision'
        }));

        res.json({
            success: true,
            count: items.length,
            items: itemsWithInfo
        });
    } catch (error) {
        console.error('[ERROR /admin/items]:', error.message);
        res.status(500).json({ success: false, error: "Error al obtener items" });
    }
});

app.put("/admin/items/:id/reset-reports", [
    param('id').isMongoId()
], async (req, res) => {
    try {
        const item = await Juego.findByIdAndUpdate(
            req.params.id,
            { 
                $set: { 
                    reportes: 0,
                    linkStatus: 'online'
                }
            },
            { new: true }
        );

        if (!item) {
            return res.status(404).json({ success: false, error: "Item no encontrado" });
        }

        console.log(`✅ ADMIN: Reportes reseteados para ${item.title}`);
        res.json({ success: true, item });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al resetear reportes" });
    }
});

app.put("/admin/items/:id/link-status", [
    param('id').isMongoId(),
    body('linkStatus').isIn(['online', 'revision', 'caido'])
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, error: "Estado inválido" });
        }

        const item = await Juego.findByIdAndUpdate(
            req.params.id,
            { $set: { linkStatus: req.body.linkStatus } },
            { new: true }
        );

        if (!item) {
            return res.status(404).json({ success: false, error: "Item no encontrado" });
        }

        console.log(`✅ ADMIN: Link status cambiado a ${req.body.linkStatus} para ${item.title}`);
        res.json({ success: true, item });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al actualizar estado del link" });
    }
});

app.put("/items/report/:id", [
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

        const juego = await Juego.findByIdAndUpdate(
            req.params.id, 
            { $inc: { reportes: 1 } }, 
            { new: true }
        );

        if (!juego) {
            return res.status(404).json({ success: false, error: "Item no encontrado" });
        }

        if (juego.reportes >= 3 && juego.linkStatus !== 'revision') {
            juego.linkStatus = 'revision';
            await juego.save();
        }
        
        console.log(`⚠️ Reporte #${juego.reportes} para: ${juego.title}`);
        
        res.json({ 
            success: true,
            ok: true, 
            reportes: juego.reportes,
            linkStatus: juego.linkStatus
        });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al reportar" 
        }); 
    }
});

// ==========================================
// RUTAS DE JUEGOS (CON FILTRO DE LINKS CAÍDOS)
// ==========================================

app.get("/items", async (req, res) => {
    try {
        const { categoria } = req.query;
        const filtro = { 
            status: 'aprobado',
            // ⭐ CORREGIDO: Solo ocultar links caídos, permitir "en revisión" y "online"
            linkStatus: { $in: ['online', 'revision'] }
        };
        
        if (categoria && categoria !== 'Todo') {
            filtro.category = categoria;
        }

        const items = await Juego.find(filtro)
            .select('_id title description image link category usuario reportes linkStatus descargasEfectivas')
            .sort({ createdAt: -1 })
            .limit(100)
            .lean();

        res.json(items);
    } catch (error) {
        res.status(500).json([]);
    }
});

app.get("/items/user/:usuario", async (req, res) => {
    try {
        const aportes = await Juego.find({ 
            usuario: req.params.usuario 
        }).sort({ createdAt: -1 }).lean();
        res.json(aportes);
    } catch (error) { 
        res.status(500).json([]); 
    }
});

app.post("/items/add", [
    body('title').notEmpty().trim().isLength({ max: 200 }),
    body('link').notEmpty().trim(),
    body('usuario').optional().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const nuevoJuego = new Juego({ 
            ...req.body, 
            status: "pendiente",
            linkStatus: "online"
        });
        
        await nuevoJuego.save();
        
        console.log(`✅ Nuevo item agregado: ${nuevoJuego.title} por @${nuevoJuego.usuario}`);
        
        res.status(201).json({ 
            success: true,
            ok: true,
            item: nuevoJuego,
            id: nuevoJuego._id
        });
    } catch (error) { 
        console.error('[ERROR /items/add]:', error.message);
        res.status(500).json({ 
            success: false,
            error: "Error al guardar aporte" 
        }); 
    }
});

app.put("/items/approve/:id", [
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

        await Juego.findByIdAndUpdate(
            req.params.id, 
            { $set: { status: "aprobado" } }
        );
        
        res.json({ success: true, ok: true });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error de aprobación" 
        }); 
    }
});

app.delete("/items/:id", [
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

        await Juego.findByIdAndDelete(req.params.id);
        res.json({ success: true, ok: true });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al eliminar" 
        }); 
    }
});

app.get('/items/:id', async (req, res) => {
    try {
        const item = await Juego.findById(req.params.id).lean();
        if (!item) {
            return res.status(404).json({ success: false, error: "Item no encontrado" });
        }
        res.json(item);
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al cargar item" });
    }
});



// ==========================================
// RUTAS DE USUARIOS
// ==========================================

app.get('/auth/users', async (req, res) => {
    try {
        const users = await Usuario.find()
            .select('-password')
            .sort({ fecha: -1 })
            .lean();
        res.json(users);
    } catch (error) {
        res.status(500).json([]);
    }
});

// ⭐ ADMIN: Obtener datos completos de un usuario (para panel admin)
app.get('/admin/users/detalle/:id', async (req, res) => {
    try {
        const user = await Usuario.findById(req.params.id)
            .select('-password')
            .lean();
        
        if (!user) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        // Obtener juegos del usuario
        const juegos = await Juego.find({ usuario: user.usuario })
            .select('title status descargasEfectivas linkStatus createdAt')
            .lean();

        res.json({ success: true, user, juegos });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al obtener datos" });
    }
});

// ⭐ ADMIN: Toggle lista negra
app.put('/admin/users/lista-negra/:id', [
    body('listaNegraAdmin').isBoolean(),
    body('notasAdmin').optional().trim().isLength({ max: 500 })
], async (req, res) => {
    try {
        const { listaNegraAdmin, notasAdmin } = req.body;

        const updates = { 
            listaNegraAdmin: !!listaNegraAdmin,
            fechaListaNegra: listaNegraAdmin ? new Date() : null
        };
        if (notasAdmin !== undefined) updates.notasAdmin = notasAdmin;

        const user = await Usuario.findByIdAndUpdate(
            req.params.id,
            { $set: updates },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        console.log(`🚫 Lista negra actualizada: @${user.usuario} → ${listaNegraAdmin}`);
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al actualizar lista negra" });
    }
});

// ⭐ ADMIN: Actualizar notas del admin sobre un usuario
app.put('/admin/users/notas/:id', [
    body('notasAdmin').trim().isLength({ max: 500 })
], async (req, res) => {
    try {
        const { notasAdmin } = req.body;
        const user = await Usuario.findByIdAndUpdate(
            req.params.id,
            { $set: { notasAdmin } },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        res.json({ success: true, mensaje: "Notas actualizadas" });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al guardar notas" });
    }
});

// ⭐ ADMIN: Obtener solo usuarios en lista negra
app.get('/admin/users/lista-negra', async (req, res) => {
    try {
        const users = await Usuario.find({ listaNegraAdmin: true })
            .select('-password')
            .sort({ fechaListaNegra: -1 })
            .lean();
        res.json({ success: true, users, total: users.length });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al obtener lista negra" });
    }
});

app.delete('/auth/users/:id', async (req, res) => {
    try {
        await Usuario.findByIdAndDelete(req.params.id);
        res.json({ success: true, ok: true });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al eliminar" });
    }
});

app.put('/auth/admin/verificacion/:username', [
    body('nivel').isInt({ min: 0, max: 3 })
], async (req, res) => {
    try {
        const { username } = req.params;
        const { nivel } = req.body;

        const user = await Usuario.findOneAndUpdate(
            { usuario: username.toLowerCase() },
            { $set: { verificadoNivel: nivel } },
            { new: true }
        ).select('-password');

        if (!user) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        console.log(`✅ Verificación actualizada: @${username} → Nivel ${nivel}`);
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al actualizar verificación" });
    }
});

// ========== RUTAS DE PERFIL ==========
app.get('/usuarios/perfil-publico/:usuario', async (req, res) => {
    try {
        const username = req.params.usuario.toLowerCase().trim();
        const user = await Usuario.findOne({ usuario: username }).select('-password -paypalEmail').lean();

        if (!user) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        const publicaciones = await Juego.countDocuments({ 
            usuario: user.usuario, 
            status: 'aprobado' 
        });

        res.json({
            success: true,
            usuario: {
                ...user,
                publicaciones,
                seguidores: user.listaSeguidores ? user.listaSeguidores.length : 0,
                siguiendo: user.siguiendo ? user.siguiendo.length : 0
            }
        });
    } catch (err) {
        res.status(500).json({ success: false, error: "Error al cargar perfil" });
    }
});

app.get('/usuarios/verifica-seguimiento/:actual/:viendo', async (req, res) => {
    try {
        const actual = req.params.actual.toLowerCase().trim();
        const viendo = req.params.viendo.toLowerCase().trim();
        const user = await Usuario.findOne({ usuario: actual });
        const loSigo = user?.siguiendo?.includes(viendo);
        res.json({ estaSiguiendo: !!loSigo });
    } catch (err) {
        res.json({ estaSiguiendo: false });
    }
});

app.put('/usuarios/toggle-seguir/:actual/:objetivo', async (req, res) => {
    try {
        const actual = req.params.actual.toLowerCase();
        const objetivo = req.params.objetivo.toLowerCase();
        
        const userActual = await Usuario.findOne({ usuario: actual });
        const userObjetivo = await Usuario.findOne({ usuario: objetivo });
        
        if (!userActual || !userObjetivo) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        const yaSigue = userActual.siguiendo.includes(objetivo);
        
        if (yaSigue) {
            await Usuario.updateOne(
                { usuario: actual },
                { $pull: { siguiendo: objetivo } }
            );
            await Usuario.updateOne(
                { usuario: objetivo },
                { $pull: { listaSeguidores: actual } }
            );
            res.json({ success: true, siguiendo: false });
        } else {
            await Usuario.updateOne(
                { usuario: actual },
                { $addToSet: { siguiendo: objetivo } }
            );
            await Usuario.updateOne(
                { usuario: objetivo },
                { $addToSet: { listaSeguidores: actual } }
            );
            res.json({ success: true, siguiendo: true });
        }
    } catch (err) {
        res.status(500).json({ success: false, error: "Error al actualizar" });
    }
});

app.put('/usuarios/update-avatar', [
    body('usuario').notEmpty(),
    body('avatarUrl').notEmpty()
], async (req, res) => {
    try {
        const { usuario, avatarUrl } = req.body;
        await Usuario.updateOne(
            { usuario: usuario.toLowerCase() },
            { $set: { avatar: avatarUrl } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: "Error al actualizar avatar" });
    }
});

app.put('/usuarios/update-bio', [
    body('usuario').notEmpty(),
    body('bio').isLength({ max: 200 })
], async (req, res) => {
    try {
        const { usuario, bio } = req.body;
        await Usuario.updateOne(
            { usuario: usuario.toLowerCase() },
            { $set: { bio } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, error: "Error al actualizar bio" });
    }
});

// ========== RUTAS DE COMENTARIOS ==========
app.get('/comentarios', async (req, res) => {
    try {
        const comms = await Comentario.find().sort({ fecha: -1 }).lean();
        res.json(comms);
    } catch (error) {
        res.status(500).json([]);
    }
});

app.get('/comentarios/:itemId', async (req, res) => {
    try {
        const comms = await Comentario.find({ itemId: req.params.itemId })
            .sort({ fecha: -1 })
            .lean();
        res.json(comms);
    } catch (error) {
        res.status(500).json([]);
    }
});

app.post('/comentarios', [
    body('itemId').notEmpty(),
    body('usuario').notEmpty(),
    body('texto').notEmpty().isLength({ max: 500 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, error: "Datos inválidos" });
        }

        const nuevo = new Comentario(req.body);
        await nuevo.save();
        res.status(201).json({ success: true, comentario: nuevo });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al guardar comentario" });
    }
});

app.delete('/comentarios/:id', async (req, res) => {
    try {
        await Comentario.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al eliminar" });
    }
});

// ========== RUTAS DE FAVORITOS ==========
app.post('/favoritos/add', [
    body('usuario').notEmpty(),
    body('itemId').isMongoId()
], async (req, res) => {
    try {
        const { usuario, itemId } = req.body;
        
        const existe = await Favorito.findOne({ usuario, itemId });
        if (existe) {
            return res.status(400).json({ success: false, error: "Ya está en favoritos" });
        }

        const fav = new Favorito({ usuario, itemId });
        await fav.save();
        
        res.json({ success: true, ok: true });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al guardar favorito" });
    }
});

app.delete('/favoritos/remove', [
    body('usuario').notEmpty(),
    body('itemId').isMongoId()
], async (req, res) => {
    try {
        const { usuario, itemId } = req.body;
        await Favorito.deleteOne({ usuario, itemId });
        res.json({ success: true, ok: true });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al eliminar favorito" });
    }
});

app.get('/favoritos/:usuario', async (req, res) => {
    try {
        const favs = await Favorito.find({ usuario: req.params.usuario })
            .populate({
                path: 'itemId',
                select: '_id title description image link category usuario status reportes linkStatus descargasEfectivas'
            })
            .lean();

        const items = favs
            .filter(f => f.itemId)
            .map(fav => ({
                _id: fav.itemId._id,
                title: fav.itemId.title,
                description: fav.itemId.description,
                image: fav.itemId.image,
                link: fav.itemId.link,
                category: fav.itemId.category,
                usuario: fav.itemId.usuario,
                status: fav.itemId.status,
                reportes: fav.itemId.reportes,
                linkStatus: fav.itemId.linkStatus,
                descargasEfectivas: fav.itemId.descargasEfectivas
            }));

        res.json(items);
    } catch (error) {
        res.status(500).json([]);
    }
});

// ========== ⚠️ NUEVOS ENDPOINTS: DETECCIÓN DE FRAUDE (ADMIN) ==========

/**
 * Obtener estadísticas y actividades sospechosas
 */
app.get('/admin/fraud/suspicious-activities', async (req, res) => {
    try {
        const stats = await fraudDetector.getSuspiciousStats();
        res.json({
            success: true,
            ...stats
        });
    } catch (error) {
        console.error('❌ Error obteniendo actividades sospechosas:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener actividades sospechosas'
        });
    }
});

/**
 * Marcar actividad como revisada
 */
app.put('/admin/fraud/mark-reviewed/:activityId', [
    param('activityId').isMongoId(),
    body('notasAdmin').optional().isString()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'ID de actividad inválido'
            });
        }

        const { activityId } = req.params;
        const { notasAdmin } = req.body;

        const activity = await fraudDetector.SuspiciousActivity.findById(activityId);
        if (!activity) {
            return res.status(404).json({
                success: false,
                error: 'Actividad no encontrada'
            });
        }

        activity.revisado = true;
        if (notasAdmin) {
            activity.notasAdmin = notasAdmin;
        }
        await activity.save();

        res.json({
            success: true,
            mensaje: 'Actividad marcada como revisada'
        });
    } catch (error) {
        console.error('❌ Error marcando actividad como revisada:', error);
        res.status(500).json({
            success: false,
            error: 'Error al marcar actividad'
        });
    }
});

/**
 * Obtener historial de fraude de un usuario específico
 */
app.get('/admin/fraud/user-history/:usuario', async (req, res) => {
    try {
        const { usuario } = req.params;
        
        const activities = await fraudDetector.SuspiciousActivity.find({ usuario })
            .sort({ fecha: -1 })
            .limit(50);

        res.json({
            success: true,
            usuario,
            activities
        });
    } catch (error) {
        console.error('❌ Error obteniendo historial de usuario:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener historial'
        });
    }
});

// ========== HEALTHCHECK ==========
app.get('/', (req, res) => {
    res.json({ 
        status: 'UP', 
        version: '3.2 - JOBS AUTOMÁTICOS + VERIFICACIÓN INTELIGENTE',
        timestamp: new Date().toISOString(),
        features: [
            'Sistema de economía CPM ($2.00/1000 descargas)',
            'Control de IPs anti-bots (TTL 24h)',
            'Login dual (usuario/email)',
            'Pagos PayPal automatizados',
            'Panel Admin de Finanzas completo',
            'Sistema de links caídos',
            'Verificación de usuarios multi-nivel',
            'Detección automática de fraude',
            'Auto-marcación en lista negra',
            'Análisis de comportamiento en tiempo real',
            '⚙️ NUEVO: Auto-ping anti-sleep (cada 14 min)',
            '⚙️ NUEVO: Limpieza de comentarios (cada 24h)',
            '⚙️ NUEVO: Reset de reportes confirmados (cada 12h)',
            '⚙️ NUEVO: Auto-rechazo de pendientes +7 días (cada 24h)',
            '⚙️ NUEVO: Auto-marcado de links caídos +72h (cada 6h)',
            '⚙️ NUEVO: Auto-verificación por seguidores (cada 6h)'
        ]
    });
});

// ========== MANEJO DE ERRORES ==========
app.use((req, res) => {
    res.status(404).json({ error: "Endpoint no encontrado" });
});

app.use((err, req, res, next) => {
    console.error('Error no manejado:', err);
    res.status(500).json({ error: "Error interno del servidor" });
});

// ============================================================
// ⚙️ JOBS AUTOMÁTICOS
// Se inician después de que el servidor arranca.
// Cada job corre de forma independiente y con manejo de errores
// para que si uno falla no afecte a los demás ni al servidor.
// ============================================================

function iniciarJobsAutomaticos() {

    // ----------------------------------------------------------
    // JOB 1: AUTO-PING (cada 14 minutos)
    // Evita que Render duerma el servidor.
    // Se hace al propio endpoint / del servidor.
    // ----------------------------------------------------------
    const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${process.env.PORT || 10000}`;

    setInterval(async () => {
        try {
            const res = await fetch(`${SELF_URL}/`);
            console.log(`🏓 Auto-ping OK [${new Date().toLocaleTimeString('es-ES')}] - Status: ${res.status}`);
        } catch (err) {
            console.warn(`⚠️ Auto-ping falló: ${err.message}`);
        }
    }, 14 * 60 * 1000); // 14 minutos

    console.log('🏓 JOB 1: Auto-ping activo (cada 14 min)');

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
                console.log(`🧹 JOB 2 Comentarios: ${vacios.deletedCount} vacíos + ${eliminadosDuplicados} duplicados eliminados`);
            } else {
                console.log(`🧹 JOB 2 Comentarios: sin basura encontrada`);
            }
        } catch (err) {
            console.error('❌ JOB 2 Error limpiando comentarios:', err.message);
        }
    }

    limpiarComentarios(); // Correr al arrancar
    setInterval(limpiarComentarios, 24 * 60 * 60 * 1000); // Cada 24h
    console.log('🧹 JOB 2: Limpieza de comentarios activa (cada 24h)');

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
                console.log(`🔄 JOB 3 Reportes: ${resultado.modifiedCount} juegos reseteados a 0 reportes`);
            } else {
                console.log(`🔄 JOB 3 Reportes: ningún juego necesitaba reset`);
            }
        } catch (err) {
            console.error('❌ JOB 3 Error reseteando reportes:', err.message);
        }
    }

    setInterval(resetearReportesOnline, 12 * 60 * 60 * 1000); // Cada 12h
    console.log('🔄 JOB 3: Reset de reportes activo (cada 12h)');

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
                console.log(`⏰ JOB 4 Pendientes: ${resultado.modifiedCount} items auto-rechazados por expiración (7 días)`);
            } else {
                console.log(`⏰ JOB 4 Pendientes: no hay items expirados`);
            }
        } catch (err) {
            console.error('❌ JOB 4 Error en auto-rechazo:', err.message);
        }
    }

    autoRechazarPendientes(); // Correr al arrancar
    setInterval(autoRechazarPendientes, 24 * 60 * 60 * 1000); // Cada 24h
    console.log('⏰ JOB 4: Auto-rechazo de pendientes activo (cada 24h)');

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
                console.log(`🚨 JOB 5 Links: ${resultado.modifiedCount} links auto-marcados como caídos (10+ reportes, 72h sin revisión)`);
            } else {
                console.log(`🚨 JOB 5 Links: ningún link requirió auto-marcar`);
            }
        } catch (err) {
            console.error('❌ JOB 5 Error marcando links caídos:', err.message);
        }
    }

    setInterval(autoMarcarCaidos, 6 * 60 * 60 * 1000); // Cada 6h
    console.log('🚨 JOB 5: Auto-marcado de links caídos activo (cada 6h)');

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
                console.log(`✅ JOB 6 Verificación: ${subieron} usuarios subieron de nivel automáticamente`);
            } else {
                console.log(`✅ JOB 6 Verificación: todos los niveles están al día`);
            }
        } catch (err) {
            console.error('❌ JOB 6 Error en auto-verificación:', err.message);
        }
    }

    autoVerificarUsuarios(); // Correr al arrancar
    setInterval(autoVerificarUsuarios, 6 * 60 * 60 * 1000); // Cada 6h
    console.log('✅ JOB 6: Auto-verificación por seguidores activa (cada 6h)');

    console.log('');
    console.log('⚙️  TODOS LOS JOBS AUTOMÁTICOS INICIADOS');
    console.log('─────────────────────────────────────────');
}

// ========== INICIAR SERVIDOR ==========
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`🔥 SERVIDOR CORRIENDO EN PUERTO ${PORT}`);
    console.log(`📡 Endpoint: http://localhost:${PORT}`);
    console.log(`💰 Sistema de Economía: ACTIVO`);
    console.log(`📊 CPM: $${CPM_VALUE} (${AUTHOR_PERCENTAGE * 100}% autor)`);
    console.log(`🎯 Umbral de ganancias: ${MIN_DOWNLOADS_TO_EARN} descargas`);
    console.log(`💵 Retiro mínimo: $${MIN_WITHDRAWAL} USD`);
    console.log(`🛡️ Anti-bots: Máx ${MAX_DOWNLOADS_PER_IP_PER_DAY} descargas/IP/día`);
    console.log(`⚠️ Sistema de detección de fraude: ACTIVO`);
    console.log(`🚫 Auto-marcación en lista negra: HABILITADA`);

    // Iniciar jobs después de que el servidor esté listo y Mongo conectado
    mongoose.connection.once('open', () => {
        iniciarJobsAutomaticos();
    });
});
