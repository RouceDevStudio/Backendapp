const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// --- CONFIGURACIÓN DE SEGURIDAD ---
// Permite que tu frontend se comunique con el backend sin bloqueos de red
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));
app.use(express.json());

// 1. CONEXIÓN A MONGODB ATLAS
// Se mantiene tu URI original para no perder la base de datos
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority";

mongoose.connect(uri)
  .then(() => console.log("🚀 CONEXIÓN EXITOSA: La base de datos está lista."))
  .catch(err => console.error("❌ ERROR DE CONEXIÓN A MONGO:", err));

// 2. MODELO DE DATOS FLEXIBLE
// El parámetro { strict: false } evita errores si el frontend envía datos extras
const JuegoSchema = new mongoose.Schema({}, { strict: false, timestamps: true });
const Juego = mongoose.model('Juego', JuegoSchema);

// 3. RUTA DE BIENVENIDA (Para verificar estado desde el navegador)
app.get("/", (req, res) => {
    res.send("🚀 El backend de UpGames está en línea y funcionando.");
});

// 4. RUTA PARA OBTENER TODOS LOS JUEGOS (GET)
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find();
        res.json(juegos);
    } catch (error) {
        res.status(500).json({ error: "Error al leer datos", detalle: error.message });
    }
});

// 5. RUTA PARA AGREGAR JUEGOS (POST)
// Aquí es donde se solucionó el "Error interno" que mostraba tu alerta
app.post("/items/add", async (req, res) => {
    try {
        console.log("Datos recibidos para guardar:", req.body);
        
        // Creamos el juego asegurando que tenga un estado inicial
        const nuevoJuego = new Juego({
            ...req.body,
            status: "pendiente"
        });

        await nuevoJuego.save();
        res.status(201).json({ ok: true, mensaje: "Juego guardado correctamente." });
    } catch (error) {
        console.error("Error al guardar:", error);
        res.status(500).json({ error: "Error interno del servidor", detalle: error.message });
    }
});

// 6. RUTAS DE ADMINISTRACIÓN (Aprobar y Eliminar)
app.put("/items/approve/:id", async (req, res) => {
    try {
        await Juego.findByIdAndUpdate(req.params.id, { status: "aprobado" });
        res.json({ ok: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete("/items/:id", async (req, res) => {
    try {
        await Juego.findByIdAndDelete(req.params.id);
        res.json({ ok: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 7. CONFIGURACIÓN DEL PUERTO PARA RENDER
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Servidor escuchando en el puerto ${PORT}`);
});
