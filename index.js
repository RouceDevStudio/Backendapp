const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// --- SISTEMA DE LOGS (Auditoría en tiempo real) ---
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`[LOG] ${req.method} ${req.path} - \( {res.statusCode} ( \){duration}ms)`);
    });
    next();
});

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// 1. CONEXIÓN A MONGODB (Pool de conexiones optimizado)
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";
mongoose.connect(uri, { maxPoolSize: 10 })
  .then(() => console.log("🚀 NÚCLEO CLOUD CONECTADO Y RASTREADO"))
  .catch(err => console.error("❌ CRITICAL_ERROR CONEXIÓN:", err));

// 2. MODELOS DE DATOS CON ÍNDICES
const JuegoSchema = new mongoose.Schema({
    usuario: { type: String, default: "Cloud User", index: true },
    title: { type: String, required: true },
    description: String,
    image: String,
    link: String,
    status: { type: String, default: "pendiente", index: true },
    reportes: { type: Number, default: 0 },
    category: { type: String, default: "General" },
    tags: [String]
}, { timestamps: true });

const Juego = mongoose.models.Juego || mongoose.model('Juego', JuegoSchema);

const UsuarioSchema = new mongoose.Schema({
    usuario: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    reputacion: { type: Number, default: 0 },
    // ESTA ES LA LÍNEA QUE AGREGAMOS:
    listaSeguidores: { type: [String], default: [] }, 
    seguidores: { type: Number, default: 0 },
    verificadoNivel: { type: Number, default: 0, min: 0, max: 3 },
    avatar: { type: String, default: "" },
    fecha: { type: Date, default: Date.now }
}, { collection: 'usuarios' });


// Índices adicionales para búsquedas rápidas
UsuarioSchema.index({ verificadoNivel: 1 });
UsuarioSchema.index({ seguidores: -1 });

const Usuario = mongoose.models.Usuario || mongoose.model("Usuario", UsuarioSchema);

// Helper para actualizar nivel de verificación (solo sube, nunca baja)
UsuarioSchema.methods.actualizarVerificacionAuto = async function () {
    let nuevoNivel = 0;
    if (this.seguidores >= 1000)      nuevoNivel = 3;
    else if (this.seguidores >= 100)  nuevoNivel = 2;
    else if (this.seguidores >= 50)   nuevoNivel = 1;

    if (nuevoNivel > this.verificadoNivel) {
        this.verificadoNivel = nuevoNivel;
        await this.save();
        console.log(`[VERIF AUTO] @${this.usuario} subió a nivel \( {nuevoNivel} ( \){this.seguidores} seguidores)`);
    }
};

const ComentarioSchema = new mongoose.Schema({
    usuario: String,
    texto: String,
    itemId: { type: String, index: true },
    fecha: { type: Date, default: Date.now }
});

const Comentario = mongoose.models.Comentario || mongoose.model('Comentario', ComentarioSchema);

const FavoritoSchema = new mongoose.Schema({
    usuario: { type: String, index: true },
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego', index: true }
});

const Favorito = mongoose.models.Favorito || mongoose.model('Favorito', FavoritoSchema);

// 3. RUTAS DE JUEGOS
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find().sort({ createdAt: -1 }).lean();
        res.json(juegos);
    } catch (error) { 
        console.error(`[ERR_ITEMS] ${error.message}`);
        res.status(500).json({ error: "Internal Error" }); 
    }
});

app.get("/items/user/:usuario", async (req, res) => {
    try {
        const aportes = await Juego.find({ usuario: req.params.usuario }).sort({ createdAt: -1 }).lean();
        res.json(aportes);
    } catch (error) { res.status(500).json([]); }
});

app.post("/items/add", async (req, res) => {
    try {
        const nuevoJuego = new Juego({ ...req.body, status: "pendiente" });
        await nuevoJuego.save();
        res.status(201).json({ ok: true });
    } catch (error) { 
        console.error(`[ERR_ADD_ITEM] Data: ${JSON.stringify(req.body)} - ${error.message}`);
        res.status(500).json({ error: "Error al guardar aporte" }); 
    }
});

app.put("/items/approve/:id", async (req, res) => {
    try {
        await Juego.findByIdAndUpdate(req.params.id, { $set: { status: "aprobado" } });
        res.json({ ok: true });
    } catch (error) { res.status(500).json({ error: "Error de aprobación" }); }
});

app.delete("/items/:id", async (req, res) => {
    try {
        await Juego.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).json({ error: "Error al eliminar" }); }
});

app.put("/items/report/:id", async (req, res) => {
    try {
        const juego = await Juego.findByIdAndUpdate(req.params.id, { $inc: { reportes: 1 } }, { new: true, lean: true });
        res.json({ ok: true, reportes: juego.reportes });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});

// 4. RUTAS DE COMENTARIOS
app.get("/comentarios", async (req, res) => {
    try {
        const comentarios = await Comentario.find().sort({ fecha: -1 }).lean();
        res.json(comentarios);
    } catch (error) { res.status(500).json([]); }
});

app.get("/comentarios/:id", async (req, res) => {
    try {
        const comentarios = await Comentario.find({ itemId: req.params.id }).sort({ fecha: -1 }).lean();
        res.json(comentarios);
    } catch (error) { res.status(500).json([]); }
});

app.post("/comentarios", async (req, res) => {
    try {
        const nuevo = new Comentario(req.body);
        await nuevo.save();
        res.status(201).json({ ok: true });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});

app.delete("/comentarios/:id", async (req, res) => {
    try {
        await Comentario.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});

// 5. RUTAS DE FAVORITOS
app.post("/favoritos/add", async (req, res) => {
    try {
        const { usuario, itemId } = req.body;
        const existe = await Favorito.findOne({ usuario, itemId }).lean();
        if (existe) return res.status(400).json({ mensaje: "Ya existe" });
        await new Favorito({ usuario, itemId }).save();
        res.json({ ok: true });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});

app.get("/favoritos/:usuario", async (req, res) => {
    try {
        const lista = await Favorito.find({ usuario: req.params.usuario }).populate('itemId').lean();
        res.json(lista);
    } catch (error) { res.status(500).json([]); }
});

app.delete("/favoritos/delete/:id", async (req, res) => {
    try {
        await Favorito.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});

// 6. USUARIOS Y AUTH
app.post("/auth/login", async (req, res) => {
    try {
        const { usuario, password } = req.body;
        const user = await Usuario.findOne({ usuario, password }).select('usuario verificadoNivel avatar').lean();
        if (user) {
            console.log(`[AUTH] Login exitoso: @${usuario}`);
            res.json({ success: true, usuario: user.usuario, verificadoNivel: user.verificadoNivel || 0 });
        } else {
            console.warn(`[AUTH] Intento fallido: @${usuario}`);
            res.status(401).json({ success: false, mensaje: "Credenciales incorrectas" });
        }
    } catch (e) { res.status(500).json({ success: false }); }
});

app.post("/auth/register", async (req, res) => {
    try {
        const { usuario, password } = req.body;
        const existe = await Usuario.findOne({ usuario }).select('_id').lean();
        if (existe) return res.status(400).json({ success: false, mensaje: "Usuario ya existe" });
        const nuevo = new Usuario({ usuario, password });
        await nuevo.save();
        console.log(`[AUTH] Nuevo registro: @${usuario}`);
        res.json({ success: true, usuario: nuevo.usuario, verificadoNivel: 0 });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.get("/auth/users", async (req, res) => {
    try {
        const usuarios = await Usuario.find().select('-password').lean();
        res.json(usuarios);
    } catch (error) { res.status(500).json([]); }
});

app.delete("/auth/users/:id", async (req, res) => {
    try {
        await Usuario.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).json({ error: "Error" }); }
});

app.put("/auth/follow/:usuario", async (req, res) => {
    try {
        const { accion, seguidor } = req.body;
        const target = req.params.usuario;
        
        if (!seguidor || !target) {
            return res.status(400).json({ success: false, mensaje: "Datos incompletos" });
        }
        
        const user = await Usuario.findOne({ usuario: target });
        if (!user) return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });
        
        // Inicializar array si no existe
        if (!user.listaSeguidores) user.listaSeguidores = [];
        
        let yaEstaba = user.listaSeguidores.includes(seguidor);
        
        if (accion === "incrementar") {
            if (!yaEstaba) {
                user.listaSeguidores.push(seguidor);
            }
        } else {
            if (yaEstaba) {
                user.listaSeguidores = user.listaSeguidores.filter(s => s !== seguidor);
            }
        }
        
        // CRÍTICO: Sincronizar el contador con la lista real
        user.seguidores = user.listaSeguidores.length;
        
        await user.save();
        await user.actualizarVerificacionAuto();
        
        console.log(`[FOLLOW] @${seguidor} ${accion === "incrementar" ? "siguió" : "dejó de seguir"} a @${target}. Total: ${user.seguidores}`);
        
        res.json({
            success: true,
            seguidores: user.seguidores,
            listaSeguidores: user.listaSeguidores,
            verificadoNivel: user.verificadoNivel,
            ahoraEstaSiguiendo: user.listaSeguidores.includes(seguidor)
        });
    } catch (e) {
        console.error("[ERROR FOLLOW]", e);
        res.status(500).json({ success: false, mensaje: e.message });
    }
});
// Nueva ruta: actualizar verificación manual (para admin)
app.put("/auth/admin/verificacion/:usuario", async (req, res) => {
    try {
        const { nivel } = req.body;
        if (!Number.isInteger(nivel) || nivel < 0 || nivel > 3) {
            return res.status(400).json({ success: false, mensaje: "Nivel inválido (0-3)" });
        }

        const user = await Usuario.findOneAndUpdate(
            { usuario: req.params.usuario },
            { verificadoNivel: nivel },
            { new: true, lean: true }
        );

        if (!user) return res.status(404).json({ success: false, mensaje: "Usuario no encontrado" });

        console.log(`[VERIF MANUAL] @${user.usuario} establecido a nivel ${nivel} por admin`);

        res.json({ success: true, verificadoNivel: user.verificadoNivel });
    } catch (e) {
        console.error("[ERR_VERIF_MANUAL]", e);
        res.status(500).json({ success: false });
    }
});

app.put("/auth/update-avatar", async (req, res) => {
    try {
        const { usuario, nuevaFoto } = req.body;
        await Usuario.findOneAndUpdate({ usuario }, { $set: { avatar: nuevaFoto } });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ success: false }); }
});

// --- CAPTURADOR DE ERRORES GLOBAL (Para evitar caídas) ---
app.use((err, req, res, next) => {
    console.error(`[CRASH_PREVENT] Error en ${req.method} ${req.path}:`, err.stack);
    res.status(500).json({ error: "Critical System Error" });
});

// 7. ARRANQUE
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
    =========================================
    ✅ NÚCLEO ACTIVO EN PUERTO ${PORT}
    📡 MONITOREO DE LOGS: ACTIVADO
    🛡️ PROTECCIÓN DE CRASH: ACTIVADA
    =========================================
    `);
});