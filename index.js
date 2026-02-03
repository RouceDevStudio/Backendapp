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
    password: { 
        type: String, 
        required: true,
        minlength: 6
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

const Usuario = mongoose.model('Usuario', UsuarioSchema);

// ========== MIDDLEWARE DE AUTENTICACIÓN JWT ==========
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: "Token no proporcionado" 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                error: "Token inválido o expirado" 
            });
        }
        req.user = user; // Guardamos el usuario decodificado
        next();
    });
};

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
    body('password').isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Usuario: 3-20 caracteres, Contraseña: min 6" 
            });
        }

        const { usuario, password } = req.body;
        
        const existe = await Usuario.findOne({ usuario });
        if (existe) {
            return res.status(400).json({ 
                success: false, 
                error: "Usuario ya existe" 
            });
        }

        const hash = await bcrypt.hash(password, 10);
        const nuevoUser = new Usuario({ 
            usuario, 
            password: hash 
        });
        
        await nuevoUser.save();

        const token = jwt.sign({ usuario }, JWT_SECRET, { expiresIn: '30d' });

        console.log(`✅ Nuevo usuario registrado: @${usuario}`);
        
        res.status(201).json({ 
            success: true,
            ok: true,
            usuario,
            token
        });
    } catch (error) {
        console.error('[ERROR /auth/register]:', error.message);
        res.status(500).json({ 
            success: false,
            error: "Error en registro" 
        });
    }
});

app.post('/auth/login', [
    body('usuario').notEmpty().trim(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Credenciales inválidas" 
            });
        }

        const { usuario, password } = req.body;
        const user = await Usuario.findOne({ usuario: usuario.toLowerCase() });

        if (!user) {
            return res.status(401).json({ 
                success: false,
                error: "Usuario no existe" 
            });
        }

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) {
            return res.status(401).json({ 
                success: false,
                error: "Contraseña incorrecta" 
            });
        }

        const token = jwt.sign({ usuario: user.usuario }, JWT_SECRET, { expiresIn: '30d' });

        console.log(`✅ Login exitoso: @${user.usuario}`);
        
        res.json({ 
            success: true,
            ok: true,
            usuario: user.usuario,
            token
        });
    } catch (error) {
        console.error('[ERROR /auth/login]:', error.message);
        res.status(500).json({ 
            success: false,
            error: "Error en login" 
        });
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
        const user = await Usuario.findOne({ usuario: username }).select('-password').lean();

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

// ========== RUTA DE SEGUIMIENTO CON AUTENTICACIÓN ==========
app.put('/auth/follow/:usuario', authenticateToken, async (req, res) => {
    try {
        const usuarioActual = req.user.usuario.toLowerCase(); // Del token JWT
        const usuarioObjetivo = req.params.usuario.toLowerCase();
        
        // Validar que no se siga a sí mismo
        if (usuarioActual === usuarioObjetivo) {
            return res.status(400).json({ 
                success: false, 
                error: "No puedes seguirte a ti mismo" 
            });
        }

        // Buscar ambos usuarios
        const userActual = await Usuario.findOne({ usuario: usuarioActual });
        const userObjetivo = await Usuario.findOne({ usuario: usuarioObjetivo });
        
        if (!userActual) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario autenticado no encontrado" 
            });
        }

        if (!userObjetivo) {
            return res.status(404).json({ 
                success: false, 
                error: "Usuario a seguir no encontrado" 
            });
        }

        // Verificar si ya sigue al usuario
        const yaSigue = userActual.siguiendo && userActual.siguiendo.includes(usuarioObjetivo);
        
        if (yaSigue) {
            // DEJAR DE SEGUIR
            await Usuario.updateOne(
                { usuario: usuarioActual },
                { $pull: { siguiendo: usuarioObjetivo } }
            );
            await Usuario.updateOne(
                { usuario: usuarioObjetivo },
                { $pull: { listaSeguidores: usuarioActual } }
            );
            
            console.log(`💔 ${usuarioActual} dejó de seguir a ${usuarioObjetivo}`);
            return res.json({ 
                success: true, 
                siguiendo: false,
                message: `Dejaste de seguir a @${usuarioObjetivo}`
            });
        } else {
            // SEGUIR
            await Usuario.updateOne(
                { usuario: usuarioActual },
                { $addToSet: { siguiendo: usuarioObjetivo } }
            );
            await Usuario.updateOne(
                { usuario: usuarioObjetivo },
                { $addToSet: { listaSeguidores: usuarioActual } }
            );
            
            console.log(`✅ ${usuarioActual} ahora sigue a ${usuarioObjetivo}`);
            return res.json({ 
                success: true, 
                siguiendo: true,
                message: `Ahora sigues a @${usuarioObjetivo}`
            });
        }
    } catch (err) {
        console.error("❌ Error en /auth/follow:", err);
        res.status(500).json({ 
            success: false, 
            error: "Error al procesar seguimiento" 
        });
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
