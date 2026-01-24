const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// --- SEGURIDAD TOTAL ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));
app.use(express.json());

// 1. CONEXIÓN A MONGODB ATLAS
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";

mongoose.connect(uri)
  .then(() => console.log("🚀 BASE DE DATOS CONECTADA"))
  .catch(err => console.error("❌ ERROR MONGO:", err));

// 2. MODELO DE DATOS FLEXIBLE
const JuegoSchema = new mongoose.Schema({
    title: String,
    description: String,
    link: String,
    image: String,
    status: { type: String, default: "pendiente" }
}, { strict: false }); // 'strict: false' permite que MongoDB guarde los datos aunque varíen un poco

const Juego = mongoose.model('Juego', JuegoSchema);

// 3. RUTA DE BIENVENIDA
app.get("/", (req, res) => res.send("🚀 SERVIDOR UP-GAMES ONLINE"));

// 4. RUTA PARA OBTENER JUEGOS
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find();
        res.json(juegos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 5. RUTA PARA PUBLICAR JUEGOS (Aquí estaba el fallo)
app.post("/items/add", async (req, res) => {
    try {
        console.log("Datos recibidos:", req.body); // Esto aparecerá en los logs de Render
        
        const nuevoJuego = new Juego(req.body);
        const guardado = await nuevoJuego.save();
        
        console.log("Juego guardado con ID:", guardado._id);
        res.status(201).json({ ok: true, id: guardado._id });
    } catch (error) {
        console.error("DETALLE DEL ERROR:", error);
        res.status(500).json({ error: "Error interno del servidor", detalles: error.message });
    }
});

// 6. RUTAS DE ADMIN (Aprobar y Borrar)
app.put("/items/approve/:id", async (req, res) => {
    try {
        await Juego.findByIdAndUpdate(req.params.id, { status: "aprobado" });
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

app.delete("/items/:id", async (req, res) => {
    try {
        await Juego.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) { res.status(500).send(error); }
});

// 7. PUERTO
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ PUERTO ${PORT}`);
});
