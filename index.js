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
const Juego = mongoose.model('Juego', new mongoose.Schema({
    usuario: String,
    title: String,
    description: String,
    image: String,
    link: String,
    status: { type: String, default: "pendiente" },
    reportes: { type: Number, default: 0 },
    category: String,
    tags: [String]
}, { timestamps: true }));

const Usuario = mongoose.models.Usuario || mongoose.model("Usuario", new mongoose.Schema({
    usuario: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    reputacion: { type: Number, default: 0 },
    fecha: { type: Date, default: Date.now }
}, { collection: 'usuarios' }));

const Comentario = mongoose.model('Comentario', new mongoose.Schema({
    usuario: String,
    texto: String,
    itemId: String,
    fecha: { type: Date, default: Date.now }
}));

const Favorito = mongoose.model('Favorito', new mongoose.Schema({
    usuario: String,
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: 'Juego' }
}));

// 3. RUTAS DE JUEGOS (PÚBLICO Y ADMIN)
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find().sort({ createdAt: -1 });
        res.json(juegos);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post("/items/add", async (req, res) => {
    try {
        const nuevoJuego = new Juego({ ...req.body, status: "pendiente" });
        await nuevoJuego.save();
        res.status(201).json({ ok: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// APROBAR JUEGO (ADMIN)
app.put("/items/approve/:id", async (req, res) => {
    try {
        await Juego.findByIdAndUpdate(req.params.id, { status: "aprobado" });
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

// ELIMINAR JUEGO (ADMIN)
app.delete("/items/:id", async (req, res) => {
    try {
        await Juego.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

app.put("/items/report/:id", async (req, res) => {
    try {
        const juego = await Juego.findByIdAndUpdate(req.params.id, { $inc: { reportes: 1 } }, { new: true });
        res.json({ ok: true, reportes: juego.reportes });
    } catch (error) { res.status(500).send(error); }
});

// 4. RUTAS DE COMENTARIOS
app.get("/comentarios", async (req, res) => { // Todos los comentarios (Para Admin)
    try {
        const comentarios = await Comentario.find().sort({ fecha: -1 });
        res.json(comentarios);
    } catch (error) { res.status(500).send(error); }
});

app.get("/comentarios/:id", async (req, res) => { // Filtrados por Juego (Para App)
    try {
        const comentarios = await Comentario.find({ itemId: req.params.id }).sort({ fecha: -1 });
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

// 5. RUTAS DE FAVORITOS
app.post("/favoritos/add", async (req, res) => {
    try {
        const { usuario, itemId } = req.body;
        const existe = await Favorito.findOne({ usuario, itemId });
        if (existe) return res.status(400).json({ mensaje: "Ya existe" });
        await new Favorito({ usuario, itemId }).save();
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

app.get("/favoritos/:usuario", async (req, res) => {
    try {
        const lista = await Favorito.find({ usuario: req.params.usuario }).populate('itemId');
        res.json(lista);
    } catch (error) { res.status(500).send(error); }
});

app.delete("/favoritos/delete/:id", async (req, res) => {
    try {
        await Favorito.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

// 6. USUARIOS Y AUTH
app.post("/auth/login", async (req, res) => {
    const { usuario, password } = req.body;
    const user = await Usuario.findOne({ usuario, password });
    if (user) res.json({ success: true, usuario: user.usuario });
    else res.status(401).json({ success: false });
});

app.get("/auth/users", async (req, res) => {
    const usuarios = await Usuario.find();
    res.json(usuarios);
});

app.delete("/auth/users/:id", async (req, res) => {
    try {
        await Usuario.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

// 7. ARRANQUE
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => console.log(`✅ NÚCLEO ACTIVO EN PUERTO ${PORT}`));
