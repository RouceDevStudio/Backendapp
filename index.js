const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// 1. CONEXIÓN A MONGODB
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";
mongoose.connect(uri)
  .then(() => console.log("🚀 NÚCLEO CLOUD CONECTADO"))
  .catch(err => console.error("❌ ERROR DE CONEXIÓN:", err));

// 2. MODELOS DE DATOS
// Juego con soporte para Reportes y Etiquetas de Desempeño
const Juego = mongoose.model('Juego', new mongoose.Schema({
    usuario: String,
    title: String,
    description: String,
    image: String,
    link: String,
    status: { type: String, default: "pendiente" },
    reportes: { type: Number, default: 0 }, // Para el sistema de links caídos
    tags: [String] // Para Gama Alta/Baja, etc.
}, { timestamps: true }));

const usuarioSchema = new mongoose.Schema({
    usuario: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    reputacion: { type: Number, default: 0 }, // Para el sistema de Trusted Source
    fecha: { type: Date, default: Date.now }
}, { collection: 'usuarios' });
const Usuario = mongoose.models.Usuario || mongoose.model("Usuario", usuarioSchema);

// NUEVO: Modelo de Comentarios (Playlist de Feedback)
const Comentario = mongoose.model('Comentario', new mongoose.Schema({
    usuario: String,
    texto: String,
    itemId: String, // Si es comentario de un juego, o "general" para la app
    fecha: { type: Date, default: Date.now }
}));

// NUEVO: Modelo de Favoritos (Bóveda Personal)
const Favorito = mongoose.model('Favorito', new mongoose.Schema({
    usuario: String, // Quién lo guarda
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego' } // Qué guarda
}));

// 3. RUTAS DE JUEGOS
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find().sort({ createdAt: -1 });
        res.json(juegos);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// NUEVO: Ruta para Deep Linking (Obtener un solo juego por ID)
app.get("/items/single/:id", async (req, res) => {
    try {
        const juego = await Juego.findById(req.params.id);
        res.json(juego);
    } catch (error) { res.status(404).json({ error: "Juego no encontrado" }); }
});

app.post("/items/add", async (req, res) => {
    try {
        const nuevoJuego = new Juego({ ...req.body, status: "pendiente" });
        await nuevoJuego.save();
        res.status(201).json({ ok: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// NUEVO: Ruta para Reportar Link Caído
app.put("/items/report/:id", async (req, res) => {
    try {
        const juego = await Juego.findByIdAndUpdate(req.params.id, { $inc: { reportes: 1 } }, { new: true });
        res.json({ ok: true, reportes: juego.reportes });
    } catch (error) { res.status(500).send(error); }
});

// 4. RUTAS DE COMENTARIOS (Playlist pública)
app.get("/comentarios", async (req, res) => {
    try {
        const comentarios = await Comentario.find().sort({ fecha: -1 });
        res.json(comentarios);
    } catch (error) { res.status(500).send(error); }
});

app.post("/comentarios", async (req, res) => {
    try {
        const nuevo = new Comentario(req.body);
        await nuevo.save();
        res.status(201).json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

app.delete("/comentarios/:id", async (req, res) => {
    try {
        await Comentario.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

// 5. RUTAS DE FAVORITOS (Bóveda)
app.post("/favoritos/add", async (req, res) => {
    try {
        const { usuario, itemId } = req.body;
        const existe = await Favorito.findOne({ usuario, itemId });
        if (existe) return res.status(400).json({ mensaje: "Ya está en tu bóveda" });
        const nuevoFav = new Favorito({ usuario, itemId });
        await nuevoFav.save();
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

app.get("/favoritos/:usuario", async (req, res) => {
    try {
        const lista = await Favorito.find({ usuario: req.params.usuario }).populate('itemId');
        res.json(lista);
    } catch (error) { res.status(500).send(error); }
});

// 6. AUTENTICACIÓN Y GESTIÓN DE USUARIOS
app.post("/auth/register", async (req, res) => {
    try {
        const { usuario, password } = req.body;
        const existe = await Usuario.findOne({ usuario });
        if (existe) return res.status(400).json({ mensaje: "El usuario ya existe" });
        const nuevoUsuario = new Usuario({ usuario, password });
        await nuevoUsuario.save();
        res.status(201).json({ mensaje: "Perfil Cloud creado" });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post("/auth/login", async (req, res) => {
    try {
        const { usuario, password } = req.body;
        const userEncontrado = await Usuario.findOne({ usuario, password });
        if (userEncontrado) res.json({ success: true, usuario: userEncontrado.usuario });
        else res.status(401).json({ success: false });
    } catch (error) { res.status(500).send(error); }
});

app.get("/auth/users", async (req, res) => {
    const usuarios = await Usuario.find();
    res.json(usuarios);
});

// 7. ARRANQUE
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Servidor Up-Games en puerto ${PORT}`));
