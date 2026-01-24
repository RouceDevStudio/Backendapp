const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

// --- CONFIGURACIÓN DE SEGURIDAD (CORS) ---
// Esto permite que tu GitHub Pages se conecte sin bloqueos del navegador
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// 1. CONEXIÓN A MONGODB ATLAS
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri)
  .then(() => console.log("🚀 ¡CONEXIÓN EXITOSA! UpGames ya tiene base de datos eterna."))
  .catch(err => console.error("❌ Error al conectar a MongoDB:", err));

// 2. MODELO DE DATOS (Esquema de MongoDB)
const JuegoSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    link: { type: String, required: true },
    image: String,
    status: { type: String, default: "pendiente" }
});

const Juego = mongoose.model('Juego', JuegoSchema);

// 3. RUTA DE BIENVENIDA (Para verificar que el servidor está vivo)
app.get("/", (req, res) => {
    res.send("🚀 El servidor de UpGames está despierto y funcionando correctamente.");
});

// 4. RUTA PARA OBTENER JUEGOS (Para el buscador y el admin)
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find();
        res.json(juegos);
    } catch (error) {
        res.status(500).json({ 
            error: "Error al obtener juegos", 
            detalles: error.message 
        });
    }
});

// 5. RUTA PARA PUBLICAR JUEGOS (Desde el panel de colaborador)
app.post("/items/add", async (req, res) => {
    try {
        const { title, description, link, image } = req.body;

        // Validación de campos obligatorios
        if(!title || !link) {
            return res.status(400).json({ error: "Título y Link son obligatorios." });
        }

        // Evitar duplicados por título
        const existe = await Juego.findOne({ title: title });
        if (existe) {
            return res.status(400).json({ error: "Este juego ya ha sido publicado anteriormente." });
        }

        const nuevoJuego = new Juego({
            title,
            description,
            link,
            image
        });

        await nuevoJuego.save();
        res.status(201).json({ ok: true, message: "Juego guardado con éxito." });
    } catch (error) {
        console.error("Error al guardar:", error);
        res.status(500).json({ 
            error: "Error interno del servidor al intentar guardar.", 
            detalles: error.message 
        });
    }
});

// 6. RUTA PARA APROBAR JUEGOS (Para el panel de Admin)
app.put("/items/approve/:id", async (req, res) => {
    try {
        const { id } = req.params;
        await Juego.findByIdAndUpdate(id, { status: "aprobado" });
        res.json({ ok: true, message: "Juego aprobado correctamente." });
    } catch (error) {
        res.status(500).json({ error: "Error al aprobar el juego." });
    }
});

// 7. RUTA PARA ELIMINAR JUEGOS
app.delete("/items/:id", async (req, res) => {
    try {
        const { id } = req.params;
        await Juego.findByIdAndDelete(id);
        res.json({ ok: true, message: "Juego eliminado permanentemente." });
    } catch (error) {
        res.status(500).json({ error: "Error al eliminar el juego." });
    }
});

// 8. INICIAR EL SERVIDOR (Configuración para Render)
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Servidor UpGames activo en puerto ${PORT}`);
});
