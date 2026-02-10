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

// CORS flexible para desarrollo y producción
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
            callback(null, true);
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

// Aplicar limitadores
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/items/add', createLimiter);
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

// SCHEMA: Juegos (MEJORADO CON LINK STATUS)
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
    // ⭐ NUEVO: Estado del link basado en reportes
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
    tags: [String]
}, { 
    timestamps: true
});

JuegoSchema.index({ usuario: 1, status: 1 });
JuegoSchema.index({ createdAt: -1 });
JuegoSchema.index({ linkStatus: 1 });

// ⭐ Middleware para actualizar linkStatus automáticamente basado en reportes
JuegoSchema.pre('save', function(next) {
    if (this.reportes >= 3) {
        this.linkStatus = 'revision';
    } else {
        this.linkStatus = 'online';
    }
    next();
});


// MIDDLEWARE: Verificar que el usuario está logueado
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ success: false, error: "Acceso denegado. No hay token." });
    }

    try {
        const verificado = jwt.verify(token, JWT_SECRET);
        req.userTokenData = verificado; // Guardamos los datos del token (usuario, email)
        next();
    } catch (error) {
        res.status(403).json({ success: false, error: "Token inválido o expirado" });
    }
};


const Juego = mongoose.model('Juego', JuegoSchema);

// SCHEMA: Usuarios
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
    // NUEVO: Email obligatorio y con formato validado
    email: { 
        type: String, 
        required: [true, "El correo es obligatorio para pagos"], 
        unique: true, 
        lowercase: true,
        trim: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Por favor usa un email válido']
    },
    password: { 
        type: String, 
        required: true, 
        minlength: 6
    },
    // NUEVO: Configuración de PayPal y Saldo
    paypalEmail: { 
        type: String, 
        default: '',
        lowercase: true,
        trim: true
    },
    saldo: { 
        type: Number, 
        default: 0,
        min: 0 
    },
    descargasTotales: { 
        type: Number, 
        default: 0 
    },
    // Campos anteriores...
    reputacion: { type: Number, default: 0 },
    listaSeguidores: [String],
    siguiendo: [String],
    verificadoNivel: { type: Number, default: 0, min: 0, max: 3, index: true },
    avatar: { type: String, default: "" },
    bio: { type: String, maxlength: 200, default: '' },
    fecha: { type: Date, default: Date.now }
}, { 
    collection: 'usuarios',
    timestamps: true
});


const Usuario = mongoose.model('Usuario', UsuarioSchema);

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




// RUTA PLUG-IN: Validación de economía
app.post('/items/verify-download/:id', async (req, res) => {
    try {
        const itemId = req.params.id;
        const userIP = req.ip || req.headers['x-forwarded-for'];

        // 1. Límite de 2 descargas por IP al día para ese juego
        const descargasHoy = await DescargaIP.countDocuments({ ip: userIP, itemId });
        if (descargasHoy >= 2) {
            const item = await Juego.findById(itemId);
            return res.json({ success: true, link: item.link, msg: "Límite de recompensa diario" });
        }

        // 2. Registrar IP y sumar saldo
        await new DescargaIP({ ip: userIP, itemId }).save();
        
        const item = await Juego.findByIdAndUpdate(itemId, { $inc: { descargasEfectivas: 1 } });
        
        // El creador gana el 50% (Ejemplo: $1.25 por cada 1000 = $0.00125 por click)
        const pago = 0.00125; 
        await Usuario.findOneAndUpdate(
            { usuario: item.usuario },
            { $inc: { saldo: pago, descargasTotales: 1 } }
        );

        res.json({ success: true, link: item.link });
    } catch (error) {
        res.status(500).json({ error: "Error en validación" });
    }
});


// Solo el dueño del token puede cambiar su propio PayPal
app.put('/usuarios/configurar-paypal', verificarToken, async (req, res) => {
    try {
        const { paypalEmail } = req.body;
        // Obtenemos el usuario directamente del token verificado
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
            return res.status(404).json({ success: false, error: "Usuario no encontrado en la base de datos" });
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
// ⭐ NUEVAS RUTAS ADMIN - EDICIÓN COMPLETA

// ==========================================

// ⭐ NUEVA: Actualizar cualquier campo de un item (ADMIN)
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



app.get('/admin/payments-pending', async (req, res) => {
    try {
        // Busca usuarios con más de $10 y nivel verificado
        const usuariosParaPagar = await Usuario.find({
            saldo: { $gte: 10 },
            verificacion: { $gte: 1 }
        }).select('usuario email paypalEmail saldo descargasTotales');
        
        res.json(usuariosParaPagar);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener pagos" });
    }
});


// ⭐ NUEVA: Obtener todos los items con información completa para admin
app.get("/admin/items", async (req, res) => {
    try {
        const items = await Juego.find()
            .sort({ createdAt: -1 })
            .lean();
        
        // Añadir información adicional útil para el admin
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

// ⭐ NUEVA: Resetear reportes de un item
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

// ⭐ NUEVA: Actualizar solo el linkStatus
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

// ⭐ MEJORADA: Ruta de reportar que actualiza linkStatus automáticamente
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

        // Actualizar linkStatus si llega a 3 reportes
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
// RUTAS ORIGINALES (MANTENER)
// ==========================================

// Obtener todos los items
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find().sort({ createdAt: -1 }).lean();
        res.json(juegos);
    } catch (error) { 
        console.error('[ERROR /items]:', error.message);
        res.status(500).json({ error: "Error al obtener items" }); 
    }
});

// Obtener items de un usuario específico
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

// Agregar nuevo item
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
            item: nuevoJuego
        });
    } catch (error) { 
        console.error('[ERROR /items/add]:', error.message);
        res.status(500).json({ 
            success: false,
            error: "Error al guardar aporte" 
        }); 
    }
});

// Aprobar item
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

// Eliminar item
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

// ========== RUTAS DE AUTENTICACIÓN ==========
app.post('/auth/register', [
    body('usuario').isLength({ min: 3, max: 20 }).trim().toLowerCase(),
    body('email').isEmail().withMessage('Email válido obligatorio').trim().toLowerCase(), // NUEVO
    body('password').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos: Usuario(3-20), Email válido y Contraseña(min 6)" 
            });
        }

        const { usuario, email, password } = req.body;
        
        // Verificar si el usuario O el email ya existen
        const existe = await Usuario.findOne({ $or: [{ usuario }, { email }] });
        if (existe) {
            return res.status(400).json({ 
                success: false, 
                error: existe.usuario === usuario ? "El usuario ya existe" : "El email ya está registrado" 
            });
        }

        const hash = await bcrypt.hash(password, 10);
        const nuevoUser = new Usuario({ 
            usuario,
            email, // NUEVO
            password: hash 
        });
        
        await nuevoUser.save();

        const token = jwt.sign({ usuario, email }, JWT_SECRET, { expiresIn: '30d' });

        console.log(`✅ Registro completo: @${usuario} (${email})`);
        
        res.status(201).json({ 
            success: true,
            ok: true,
            usuario,
            token
        });
    } catch (error) {
        console.error('[ERROR /auth/register]:', error.message);
        res.status(500).json({ success: false, error: "Error en registro" });
    }
});

app.post('/auth/login', [
    body('usuario').notEmpty().trim(), // Aquí puede venir el nombre o el email
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ success: false, error: "Faltan datos" });

        const { usuario, password } = req.body;
        const query = usuario.toLowerCase();

        // BUSQUEDA DUAL: Busca por nombre de usuario O por email
        const user = await Usuario.findOne({
            $or: [{ usuario: query }, { email: query }]
        });

        if (!user) {
            return res.status(401).json({ success: false, error: "Cuenta no encontrada" });
        }

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) {
            return res.status(401).json({ success: false, error: "Contraseña incorrecta" });
        }

        const token = jwt.sign({ usuario: user.usuario, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

        console.log(`✅ Login: @${user.usuario}`);
        
        res.json({ 
            success: true,
            ok: true,
            usuario: user.usuario,
            email: user.email, // Devolvemos el email para el frontend
            token
        });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error en login" });
    }
});




// Obtener todos los usuarios
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

// Eliminar usuario
app.delete('/auth/users/:id', async (req, res) => {
    try {
        await Usuario.findByIdAndDelete(req.params.id);
        res.json({ success: true, ok: true });
    } catch (error) {
        res.status(500).json({ success: false, error: "Error al eliminar" });
    }
});

// Cambiar nivel de verificación
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
        const user = await Usuario.findOne({ usuario: username }).select('-password -email -paypalEmail -saldo').lean();

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
                select: '_id title description image link category usuario status reportes linkStatus'
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
                linkStatus: fav.itemId.linkStatus
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
        version: '2.0 - ADMIN ENHANCED',
        timestamp: new Date().toISOString() 
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
});
