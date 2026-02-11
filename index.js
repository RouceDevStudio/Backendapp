require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult, param } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

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
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";
const JWT_SECRET = process.env.JWT_SECRET || "upgames_secret_key_2026_secure";

mongoose.connect(MONGODB_URI, {
    maxPoolSize: 10,
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
        required: true,
        index: true 
    },
    ip: { 
        type: String, 
        required: true,
        index: true 
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

// Índice compuesto para búsquedas rápidas
DescargaIPSchema.index({ juegoId: 1, ip: 1 });

const DescargaIP = mongoose.model('DescargaIP', DescargaIPSchema);

// ⭐ SCHEMA: Juegos (CON ECONOMÍA COMPLETA)
const JuegoSchema = new mongoose.Schema({
    usuario: { 
        type: String, 
        required: true,
        index: true,
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
        default: "pendiente",
        index: true 
    },
    linkStatus: {
        type: String,
        enum: ["online", "revision", "caido"],
        default: "online",
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
    tags: [String],
    
    // ⭐ NUEVOS CAMPOS ECONÓMICOS
    descargasEfectivas: { 
        type: Number, 
        default: 0,
        min: 0,
        index: true // Para ordenar por popularidad
    }
}, { 
    timestamps: true
});

JuegoSchema.index({ usuario: 1, status: 1 });
JuegoSchema.index({ createdAt: -1 });
JuegoSchema.index({ linkStatus: 1 });
JuegoSchema.index({ descargasEfectivas: -1 }); // Para ranking

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
                    enlace: juego.link // ⭐ CORREGIDO: usar 'link' del modelo
                });
            }
            // Incrementar contador
            registroIP.contadorHoy += 1;
            await registroIP.save();
        } else {
            // Crear nuevo registro de IP
            registroIP = new DescargaIP({
                juegoId,
                ip,
                contadorHoy: 1
            });
            await registroIP.save();
        }

        // Paso 3: Incrementar descargas efectivas del juego
        juego.descargasEfectivas += 1;
        await juego.save();

        // Paso 4: Obtener el autor del juego
        const autor = await Usuario.findOne({ usuario: juego.usuario });
        if (!autor) {
            console.warn(`⚠️ Autor no encontrado: ${juego.usuario}`);
            return res.json({
                success: true,
                descargaContada: true,
                enlace: juego.link, // ⭐ CORREGIDO: usar 'link' del modelo
                mensaje: "Descarga válida"
            });
        }

        // Paso 5: Actualizar descargas totales del autor
        autor.descargasTotales += 1;

        // Paso 6: Verificar si el juego ya pasó el umbral de 2,000 descargas
        if (juego.descargasEfectivas > MIN_DOWNLOADS_TO_EARN) {
            // Paso 7: Verificar si el autor está verificado (nivel 1+)
            if (autor.isVerificado && autor.verificadoNivel >= 1) {
                // ⭐ CÁLCULO DE GANANCIA
                // CPM = $2.00 por 1,000 descargas
                // Autor recibe 50% = $1.00 por 1,000 descargas
                // Por cada descarga efectiva: $1.00 / 1,000 = $0.001
                const ganancia = (CPM_VALUE * AUTHOR_PERCENTAGE) / 1000;
                
                autor.saldo += ganancia;
                
                console.log(`💰 Ganancia generada - Autor: @${autor.usuario}, +$${ganancia.toFixed(4)} USD`);
            } else {
                console.log(`ℹ️ Autor no verificado - @${autor.usuario} - No se suma saldo`);
            }
        } else {
            console.log(`ℹ️ Juego aún no alcanza 2,000 descargas - Actual: ${juego.descargasEfectivas}`);
        }

        await autor.save();

        console.log(`✅ Descarga efectiva validada - Juego: ${juego.title}, Total: ${juego.descargasEfectivas}`);

        res.json({
            success: true,
            descargaContada: true,
            enlace: juego.link, // ⭐ CORREGIDO: usar 'link' del modelo
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
            password: hashedPassword
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
            // ⭐ NUEVO: No mostrar links caídos en biblioteca
            linkStatus: { $ne: 'caido' }
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

// ========== HEALTHCHECK ==========
app.get('/', (req, res) => {
    res.json({ 
        status: 'UP', 
        version: '3.0 - ECONOMÍA UPGAMES COMPLETA',
        timestamp: new Date().toISOString(),
        features: [
            'Sistema de economía CPM ($2.00/1000 descargas)',
            'Control de IPs anti-bots (TTL 24h)',
            'Login dual (usuario/email)',
            'Pagos PayPal automatizados',
            'Panel Admin de Finanzas completo',
            'Sistema de links caídos',
            'Verificación de usuarios multi-nivel'
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
});
