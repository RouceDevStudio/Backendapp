const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Aumentado para soportar avatares en base64 si fuera necesario

// --- CONEXIÓN A MONGODB ---
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";
mongoose.connect(uri)
  .then(() => console.log("🚀 NÚCLEO GLOBAL SINCRONIZADO: Admin + Login + Perfiles + Juegos"))
  .catch(err => console.error("❌ ERROR DE CONEXIÓN:", err));

// --- MODELOS DE DATOS ---

// 1. Juegos (Input/Output)
const JuegoSchema = new mongoose.Schema({
    usuario: { type: String, index: true },
    title: { type: String, required: true },
    description: String,
    image: String,
    link: String,
    status: { type: String, default: "pendiente", index: true }, // 'pendiente' o 'aprobado'
    category: { type: String, default: "General" },
    reportes: { type: Number, default: 0 }
}, { timestamps: true });

const Juego = mongoose.model('Juego', JuegoSchema);

// 2. Usuarios (Login/Perfiles/Admin)
const UsuarioSchema = new mongoose.Schema({
    usuario: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    avatar: { type: String, default: "" },
    isVerified: { type: Boolean, default: false },
    rango: { type: String, default: "usuario" }, // 'usuario', 'vip', 'moderador', 'admin'
    seguidores: { type: Number, default: 0 },
    appStyle: {
        themeColor: { type: String, default: '#5EFF43' },
        layoutMode: { type: String, default: 'grid' },
        neonStyle: { type: String, default: 'static' }
    }
}, { timestamps: true });

const Usuario = mongoose.model("Usuario", UsuarioSchema);

// 3. Comentarios y Favoritos (Bóveda)
const Comentario = mongoose.model('Comentario', new mongoose.Schema({
    usuario: String, texto: String, itemId: String, fecha: { type: Date, default: Date.now }
}));

const Favorito = mongoose.model('Favorito', new mongoose.Schema({
    usuario: String,
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego' }
}));

// --- RUTAS DE SISTEMA (CONEXIÓN TOTAL) ---

// [LOGIN & REGISTRO]
app.post("/auth/login", async (req, res) => {
    const { usuario, password } = req.body;
    const user = await Usuario.findOne({ usuario, password });
    if (user) {
        res.json({ success: true, usuario: user.usuario, appStyle: user.appStyle, rango: user.rango, isVerified: user.isVerified });
    } else {
        res.status(401).json({ success: false, mensaje: "Credenciales incorrectas" });
    }
});

app.post("/auth/register", async (req, res) => {
    const { usuario, password } = req.body;
    const existe = await Usuario.findOne({ usuario });
    if (existe) return res.status(400).json({ success: false, mensaje: "El usuario ya existe" });
    const nuevo = new Usuario({ usuario, password, appStyle: { themeColor: '#5EFF43', layoutMode: 'grid' } });
    await nuevo.save();
    res.json({ success: true, usuario: nuevo.usuario });
});

// [GESTIÓN DE PERFIL & SOCIAL]
app.get("/auth/user/:usuario", async (req, res) => {
    const user = await Usuario.findOne({ usuario: req.params.usuario }).select('-password');
    res.json(user);
});

app.get("/auth/users", async (req, res) => {
    const users = await Usuario.find().select('-password');
    res.json(users);
});

app.put("/auth/update-avatar", async (req, res) => {
    await Usuario.findOneAndUpdate({ usuario: req.body.usuario }, { avatar: req.body.nuevaFoto });
    res.json({ success: true });
});

app.put("/auth/follow/:target", async (req, res) => {
    const { accion } = req.body; // 'incrementar' o 'decrementar'
    const val = accion === "incrementar" ? 1 : -1;
    await Usuario.findOneAndUpdate({ usuario: req.params.target }, { $inc: { seguidores: val } });
    res.json({ ok: true });
});

// [ADMINISTRACIÓN DE RANGOS (CONEXIÓN DIRECTA PANEL ADMIN)]
app.put("/auth/admin/update-rank", async (req, res) => {
    const { id, isVerified, rango } = req.body;
    await Usuario.findByIdAndUpdate(id, { isVerified, rango });
    res.json({ success: true });
});

app.delete("/auth/users/:id", async (req, res) => {
    await Usuario.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
});

// [GESTIÓN DE JUEGOS (INPUT/OUTPUT)]
app.get("/items", async (req, res) => {
    const juegos = await Juego.find().sort({ createdAt: -1 });
    res.json(juegos);
});

app.get("/items/user/:usuario", async (req, res) => {
    const aportes = await Juego.find({ usuario: req.params.usuario });
    res.json(aportes);
});

app.post("/items/add", async (req, res) => {
    const nuevo = new Juego({ ...req.body, status: "pendiente" });
    await nuevo.save();
    res.json({ ok: true });
});

app.put("/items/approve/:id", async (req, res) => {
    await Juego.findByIdAndUpdate(req.params.id, { status: "aprobado" });
    res.json({ ok: true });
});

app.delete("/items/:id", async (req, res) => {
    await Juego.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
});

// [BÓVEDA / FAVORITOS]
app.get("/favoritos/:usuario", async (req, res) => {
    const lista = await Favorito.find({ usuario: req.params.usuario }).populate('itemId');
    res.json(lista);
});

app.post("/favoritos/add", async (req, res) => {
    const { usuario, itemId } = req.body;
    const existe = await Favorito.findOne({ usuario, itemId });
    if (!existe) await new Favorito({ usuario, itemId }).save();
    res.json({ ok: true });
});

app.delete("/favoritos/delete/:id", async (req, res) => {
    await Favorito.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
});

// [COMENTARIOS]
app.get("/comentarios/:id", async (req, res) => {
    const c = await Comentario.find({ itemId: req.params.id }).sort({ fecha: -1 });
    res.json(c);
});

app.post("/comentarios", async (req, res) => {
    await new Comentario(req.body).save();
    res.json({ ok: true });
});

// --- LANZAMIENTO ---
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ SERVIDOR INTEGRADO ACTIVO EN PUERTO ${PORT}`);
});
