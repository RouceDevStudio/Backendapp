const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// --- CONFIGURACIÓN DE SEGURIDAD ---
app.use(cors());
app.use(express.json());

// 1. CONEXIÓN A MONGODB ATLAS
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";

mongoose.connect(uri)
  .then(() => console.log("🚀 CONEXIÓN EXITOSA CON MONGODB"))
  .catch(err => console.error("❌ ERROR DE MONGO:", err));

// 2. MODELO DE DATOS FLEXIBLE (Soluciona el Error 500)
// strict: false permite que se guarde cualquier campo que envíes desde el celular
const Juego = mongoose.model('Juego', new mongoose.Schema({}, { strict: false, timestamps: true }));

// 3. RUTA DE PRUEBA
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

// 5. RUTA PARA AGREGAR JUEGOS (POST)
app.post("/items/add", async (req, res) => {
    try {
        console.log("Datos recibidos:", req.body);
        
        // Creamos el documento con los datos del body y forzamos el estado 'pendiente'
        const nuevoJuego = new Juego({
            ...req.body,
            status: "pendiente"
        });

        await nuevoJuego.save();
        res.status(201).json({ ok: true, mensaje: "Guardado con éxito" });
    } catch (error) {
        console.error("Error al guardar:", error);
        res.status(500).json({ error: "Error interno", detalle: error.message });
    }
});

// 6. RUTAS DE ADMIN (Aprobar y Eliminar)
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

// 7. PUERTO PARA RENDER
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Servidor en puerto ${PORT}`);
});
