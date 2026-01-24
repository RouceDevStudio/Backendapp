const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// 1. CONEXIÓN A MONGODB ATLAS
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri)
  .then(() => console.log("🚀 ¡CONEXIÓN EXITOSA! UpGames ya tiene base de datos eterna."))
  .catch(err => console.error("❌ Error al conectar a MongoDB:", err));

// 2. MODELO DE DATOS
const JuegoSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    link: { type: String, required: true },
    image: String,
    status: { type: String, default: "pendiente" }
});

const Juego = mongoose.model('Juego', JuegoSchema);

// --- 🌟 AJUSTE 1: RUTA DE BIENVENIDA (Para despertar el servidor) ---
// Esto hará que cuando entres al link de Render no salga error, sino este mensaje.
app.get("/", (req, res) => {
    res.send("🚀 El servidor de UpGames está despierto y funcionando correctamente.");
});

// 3. RUTA PARA OBTENER JUEGOS
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find();
        res.json(juegos);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener juegos" });
    }
});

// 4. RUTA PARA PUBLICAR JUEGOS
app.post("/items/add", async (req, res) => {
    try {
        const { title, description, link, image } = req.body;

        const existe = await Juego.findOne({ title: title });
        if (existe) {
            return res.status(400).json({ error: "Este juego ya ha sido publicado anteriormente." });
        }

        const nuevoJuego = new Juego({ title, description, link, image });
        await nuevoJuego.save();
        res.status(201).json({ ok: true, message: "Juego guardado." });
    } catch (error) {
        res.status(500).json({ error: "Error al guardar en el servidor." });
    }
});

// --- 🌟 AJUSTE 2: PUERTO Y HOST PARA RENDER ---
// Usamos el puerto que Render asigna (10000) y escuchamos en '0.0.0.0'
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Servidor UpGames activo en puerto ${PORT}`);
});
