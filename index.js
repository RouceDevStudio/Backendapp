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
        // Permitir requests sin origin (como Postman) o de orígenes permitidos
        if (!origin || allowedOrigins.some(allowed => origin.startsWith(allowed))) {
            callback(null, true);
        } else {
            callback(null, true); // Más permisivo para evitar bloqueos
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

// SCHEMA: Juegos
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
        enum: ["pendiente", "aprobado", "rechazado"],
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
    tags: [String]
}, { 
    timestamps: true
});

JuegoSchema.index({ usuario: 1, status: 1 });
JuegoSchema.index({ createdAt: -1 });

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

// Método para actualizar verificación automática
UsuarioSchema.methods.actualizarVerificacionAuto = async function() {
    const seguidores = this.listaSeguidores?.length || 0;
    let nuevoNivel = 0;
    
    if (seguidores >= 1000) nuevoNivel = 3;
    else if (seguidores >= 100) nuevoNivel = 2;
    else if (seguidores >= 50) nuevoNivel = 1;

    if (nuevoNivel > this.verificadoNivel) {
        this.verificadoNivel = nuevoNivel;
        await this.save();
        console.log(`✨ @${this.usuario} verificado nivel ${nuevoNivel} (${seguidores} seguidores)`);
    }
};

// Índices
UsuarioSchema.index({ verificadoNivel: 1 });

const Usuario = mongoose.model("Usuario", UsuarioSchema);

// SCHEMA: Comentarios
const ComentarioSchema = new mongoose.Schema({
    usuario: String,
    texto: String,
    itemId: { type: String, index: true },
    fecha: { type: Date, default: Date.now }
});

const Comentario = mongoose.model('Comentario', ComentarioSchema);

// SCHEMA: Favoritos
const FavoritoSchema = new mongoose.Schema({
    usuario: { type: String, index: true },
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego', index: true }
}, {
    timestamps: true
});

FavoritoSchema.index({ usuario: 1, itemId: 1 }, { unique: true });

const Favorito = mongoose.model('Favorito', FavoritoSchema);

// ========== MIDDLEWARE DE AUTENTICACIÓN (OPCIONAL) ==========
const verificarTokenOpcional = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        req.usuario = null;
        return next();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded.usuario;
        req.esAdmin = decoded.esAdmin || false;
    } catch (error) {
        req.usuario = null;
    }
    
    next();
};

// Middleware que REQUIERE autenticación
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: "Token no proporcionado" 
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.usuario = decoded.usuario;
        req.esAdmin = decoded.esAdmin || false;
        next();
    } catch (error) {
        return res.status(401).json({ 
            success: false, 
            error: "Token inválido" 
        });
    }
};

const verificarAdmin = (req, res, next) => {
    if (!req.esAdmin) {
        return res.status(403).json({ 
            success: false, 
            error: "Acceso denegado - Solo administradores" 
        });
    }
    next();
};

// ========== RUTAS DE JUEGOS/ITEMS ==========

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
            status: "pendiente" 
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

// Reportar item
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
            { new: true, lean: true }
        );
        
        res.json({ 
            success: true,
            ok: true, 
            reportes: juego?.reportes || 0 
        });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al reportar" 
        }); 
    }
});

// ========== RUTAS DE COMENTARIOS ==========

// Obtener todos los comentarios
app.get("/comentarios", async (req, res) => {
    try {
        const comentarios = await Comentario.find()
            .sort({ fecha: -1 })
            .lean();
        res.json(comentarios);
    } catch (error) { 
        res.status(500).json([]); 
    }
});

// Obtener comentarios de un item específico
app.get("/comentarios/:id", async (req, res) => {
    try {
        const comentarios = await Comentario.find({ 
            itemId: req.params.id 
        }).sort({ fecha: -1 }).lean();
        res.json(comentarios);
    } catch (error) { 
        res.status(500).json([]); 
    }
});

// Agregar comentario
app.post("/comentarios", [
    body('usuario').notEmpty().trim(),
    body('texto').notEmpty().trim().isLength({ max: 500 }),
    body('itemId').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const nuevo = new Comentario(req.body);
        await nuevo.save();
        
        res.status(201).json({ 
            success: true,
            ok: true,
            comentario: nuevo
        });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al guardar comentario" 
        }); 
    }
});

// Eliminar comentario
app.delete("/comentarios/:id", [
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

        await Comentario.findByIdAndDelete(req.params.id);
        res.json({ success: true, ok: true });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al eliminar" 
        }); 
    }
});

// ========== RUTAS DE FAVORITOS ==========

// Agregar a favoritos
app.post("/favoritos/add", [
    body('usuario').notEmpty().trim(),
    body('itemId').isMongoId()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Datos inválidos" 
            });
        }

        const { usuario, itemId } = req.body;
        
        const existe = await Favorito.findOne({ usuario, itemId }).lean();
        if (existe) {
            return res.status(400).json({ 
                success: false,
                mensaje: "Ya existe en favoritos" 
            });
        }
        
        await new Favorito({ usuario, itemId }).save();
        
        res.json({ 
            success: true,
            ok: true 
        });
    } catch (error) { 
        if (error.code === 11000) {
            return res.status(400).json({ 
                success: false,
                mensaje: "Ya está en favoritos" 
            });
        }
        res.status(500).json({ 
            success: false,
            error: "Error al agregar favorito" 
        }); 
    }
});

// Obtener favoritos de un usuario
app.get("/favoritos/:usuario", async (req, res) => {
    try {
        const lista = await Favorito.find({ 
            usuario: req.params.usuario 
        }).populate('itemId').lean();
        res.json(lista);
    } catch (error) { 
        res.status(500).json([]); 
    }
});

// Eliminar de favoritos
app.delete("/favoritos/delete/:id", [
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

        await Favorito.findByIdAndDelete(req.params.id);
        res.json({ success: true, ok: true });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al eliminar" 
        }); 
    }
});

// ========== RUTAS DE AUTENTICACIÓN ==========

// Login
app.post("/auth/login", [
    body('usuario').notEmpty().trim(),
    body('password').notEmpty()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Usuario y contraseña requeridos" 
            });
        }
        
        // AGREGAR ESTO A index.js
app.get("/usuarios/perfil-publico/:usuario", async (req, res) => {
    try {
        const user = await Usuario.findOne({ 
            usuario: req.params.usuario.toLowerCase() 
        }).select('-password').lean();

        if (!user) {
            return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        }

        // Contar publicaciones aprobadas del usuario
        const conteoPublicaciones = await Juego.countDocuments({ 
            usuario: user.usuario, 
            status: 'aprobado' 
        });

        res.json({
            success: true,
            usuario: {
                ...user,
                publicaciones: conteoPublicaciones,
                seguidores: user.listaSeguidores?.length || 0,
                siguiendo: user.siguiendo?.length || 0
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// NUEVA RUTA: Obtener perfil público de un usuario


// TAMBIÉN AGREGA ESTA RUTA PARA VERIFICAR EL BOTÓN
app.get("/usuarios/verifica-seguimiento/:actual/:viendo", async (req, res) => {
    try {
        const user = await Usuario.findOne({ usuario: req.params.actual.toLowerCase() });
        const estaSiguiendo = user?.siguiendo?.includes(req.params.viendo.toLowerCase());
        res.json({ estaSiguiendo: !!estaSiguiendo });
    } catch (error) {
        res.json({ estaSiguiendo: false });
    }
});


        const { usuario, password } = req.body;
        
        // Buscar usuario
        const user = await Usuario.findOne({ 
            usuario: usuario.toLowerCase() 
        });
        
        if (!user) {
            console.warn(`❌ Login fallido: usuario no existe - @${usuario}`);
            return res.status(401).json({ 
                success: false, 
                mensaje: "Credenciales incorrectas" 
            });
        }

        // Verificar contraseña
        // Si la contraseña está hasheada, usar bcrypt
        let passwordValida = false;
        if (user.password.startsWith('$2')) {
            passwordValida = await bcrypt.compare(password, user.password);
        } else {
            // Compatibilidad con contraseñas sin hash (migración)
            passwordValida = password === user.password;
        }

        if (!passwordValida) {
            console.warn(`❌ Login fallido: contraseña incorrecta - @${usuario}`);
            return res.status(401).json({ 
                success: false, 
                mensaje: "Credenciales incorrectas" 
            });
        }

        // Generar token JWT
        const token = jwt.sign(
            { 
                usuario: user.usuario,
                esAdmin: user.usuario === 'roucedev' || user.usuario === 'admin'
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log(`✅ Login exitoso: @${usuario}`);

        res.json({ 
            success: true,
            usuario: user.usuario,
            verificadoNivel: user.verificadoNivel || 0,
            avatar: user.avatar || '',
            token
        });
    } catch (error) { 
        console.error('[ERROR /auth/login]:', error.message);
        res.status(500).json({ 
            success: false,
            mensaje: "Error del servidor" 
        }); 
    }
});

// Registro
app.post("/auth/register", [
    body('usuario').notEmpty().trim().isLength({ min: 3, max: 20 }),
    body('password').notEmpty().isLength({ min: 6 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Usuario (3-20 chars) y contraseña (min 6) requeridos" 
            });
        }

        const { usuario, password } = req.body;
        
        // Verificar si existe
        const existe = await Usuario.findOne({ 
            usuario: usuario.toLowerCase() 
        }).select('_id').lean();
        
        if (existe) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Usuario ya existe" 
            });
        }

        // Hash de contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear usuario
        const nuevo = new Usuario({ 
            usuario: usuario.toLowerCase(), 
            password: hashedPassword,
            listaSeguidores: [],
            siguiendo: []
        });
        
        await nuevo.save();

        // Generar token
        const token = jwt.sign(
            { 
                usuario: nuevo.usuario,
                esAdmin: false
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log(`✅ Nuevo registro: @${usuario}`);

        res.json({ 
            success: true,
            usuario: nuevo.usuario,
            verificadoNivel: 0,
            token
        });
    } catch (error) { 
        console.error('[ERROR /auth/register]:', error.message);
        res.status(500).json({ 
            success: false,
            mensaje: "Error del servidor" 
        }); 
    }
});

// Obtener todos los usuarios
app.get("/auth/users", async (req, res) => {
    try {
        const usuarios = await Usuario.find()
            .select('-password')
            .lean();
        res.json(usuarios);
    } catch (error) { 
        res.status(500).json([]); 
    }
});

// Obtener un usuario específico
app.get("/auth/users/:usuario", async (req, res) => {
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
        
        res.json(usuario);
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al obtener usuario" 
        }); 
    }
});

// Eliminar usuario (solo admin)
app.delete("/auth/users/:id", [
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

        await Usuario.findByIdAndDelete(req.params.id);
        res.json({ success: true, ok: true });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al eliminar" 
        }); 
    }
});

// Seguir/Dejar de seguir
app.put("/auth/follow/:usuario", [
    body('accion').isIn(['incrementar', 'decrementar']),
    body('seguidor').notEmpty().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const { accion, seguidor } = req.body;
        const target = req.params.usuario.toLowerCase();

        let query = {};
        let queryContrario = {};
        
        if (accion === "incrementar") {
            // Agregar seguidor a la lista del target
            query = { $addToSet: { listaSeguidores: seguidor } };
            // Agregar target a la lista de "siguiendo" del seguidor
            queryContrario = { $addToSet: { siguiendo: target } };
        } else {
            // Remover seguidor de la lista del target
            query = { $pull: { listaSeguidores: seguidor } };
            // Remover target de la lista de "siguiendo" del seguidor
            queryContrario = { $pull: { siguiendo: target } };
        }

        // Actualizar usuario objetivo (el que recibe el seguidor)
        const user = await Usuario.findOneAndUpdate(
            { usuario: target },
            query,
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ 
                success: false,
                mensaje: "Usuario no encontrado" 
            });
        }

        // Actualizar usuario que hace el seguimiento
        await Usuario.findOneAndUpdate(
            { usuario: seguidor },
            queryContrario
        );

        // Actualizar verificación automática
        await user.actualizarVerificacionAuto();

        console.log(`${accion === 'incrementar' ? '➕' : '➖'} @${seguidor} ${accion === 'incrementar' ? 'sigue' : 'dejó de seguir'} a @${target}`);

        res.json({ 
            success: true,
            seguidores: user.listaSeguidores?.length || 0,
            listaSeguidores: user.listaSeguidores || [],
            verificadoNivel: user.verificadoNivel
        });
    } catch (error) { 
        console.error('[ERROR /auth/follow]:', error.message);
        res.status(500).json({ 
            success: false,
            error: "Error en operación de seguimiento" 
        }); 
    }
});

// Actualizar avatar
app.put("/auth/update-avatar", [
    body('usuario').notEmpty().trim(),
    body('nuevaFoto').notEmpty().trim()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Datos inválidos" 
            });
        }

        const { usuario, nuevaFoto } = req.body;
        
        await Usuario.findOneAndUpdate(
            { usuario: usuario.toLowerCase() }, 
            { $set: { avatar: nuevaFoto } }
        );
        
        console.log(`✅ Avatar actualizado: @${usuario}`);
        
        res.json({ success: true });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al actualizar avatar" 
        }); 
    }
});

// Actualizar bio
app.put("/auth/update-bio", [
    body('usuario').notEmpty().trim(),
    body('bio').isLength({ max: 200 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: "Bio muy larga (máx 200 caracteres)" 
            });
        }

        const { usuario, bio } = req.body;
        
        await Usuario.findOneAndUpdate(
            { usuario: usuario.toLowerCase() }, 
            { $set: { bio: bio || '' } }
        );
        
        console.log(`✅ Bio actualizada: @${usuario}`);
        
        res.json({ success: true });
    } catch (error) { 
        res.status(500).json({ 
            success: false,
            error: "Error al actualizar bio" 
        }); 
    }
});

// Actualizar verificación manual (admin)
app.put("/auth/admin/verificacion/:usuario", [
    body('nivel').isInt({ min: 0, max: 3 })
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                mensaje: "Nivel debe ser 0-3" 
            });
        }

        const { nivel } = req.body;

        const user = await Usuario.findOneAndUpdate(
            { usuario: req.params.usuario.toLowerCase() },
            { verificadoNivel: nivel },
            { new: true, lean: true }
        );

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                mensaje: "Usuario no encontrado" 
            });
        }

        console.log(`✨ Verificación manual: @${user.usuario} → Nivel ${nivel}`);

        res.json({ 
            success: true, 
            verificadoNivel: user.verificadoNivel 
        });
    } catch (error) {
        console.error('[ERROR /auth/admin/verificacion]:', error.message);
        res.status(500).json({ 
            success: false,
            error: "Error al actualizar verificación" 
        });
    }
});

// ========== BÚSQUEDA ==========
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
            .select('usuario avatar verificadoNivel listaSeguidores')
            .limit(parseInt(limit))
            .lean();
            
            // Agregar contador de seguidores
            results.usuarios = results.usuarios.map(u => ({
                ...u,
                seguidores: u.listaSeguidores?.length || 0
            }));
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
        console.error('[ERROR /search]:', error.message);
        res.status(500).json({ 
            success: false,
            error: "Error en búsqueda" 
        });
    }
});

// ========== HEALTH CHECK ==========
app.get("/health", (req, res) => {
    res.json({ 
        success: true,
        status: "OK",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        version: '2.0.0'
    });
});

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "🎮 UpGames API v2.0",
        endpoints: {
            items: "/items",
            users: "/auth/users",
            health: "/health"
        }
    });
});

// ========== MANEJO DE ERRORES ==========
app.use((err, req, res, next) => {
    console.error(`❌ Error en ${req.method} ${req.path}:`, err.message);

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
            error: "Registro duplicado"
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
        error: "Error del servidor" 
    });
});

// Ruta no encontrada
app.use((req, res) => {
    res.status(404).json({ 
        success: false,
        error: "Ruta no encontrada",
        path: req.path
    });
});

// ========== SEÑALES DE TERMINACIÓN ==========
process.on('SIGTERM', async () => {
    console.log('⚠️ SIGTERM recibido. Cerrando servidor...');
    await mongoose.connection.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('⚠️ SIGINT recibido. Cerrando servidor...');
    await mongoose.connection.close();
    process.exit(0);
});

// ========== INICIO DEL SERVIDOR ==========
const PORT = process.env.PORT || 10000;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
    ╔════════════════════════════════════════╗
    ║   🎮 UPGAMES API v2.0                 ║
    ║   ✅ Servidor: http://0.0.0.0:${PORT}   ║
    ║   📡 MongoDB: Conectado                ║
    ║   🛡️  Seguridad: Activada              ║
    ╚════════════════════════════════════════╝
    `);
});

module.exports = app;
