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

// 2. MODELO DE DATOS (El "molde" para la base de datos)
const JuegoSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: String,
    link: { type: String, required: true },
    image: String,
    status: { type: String, default: "pendiente" } // Para tu sistema de aprobación
});

const Juego = mongoose.model('Juego', JuegoSchema);

// 3. RUTA PARA OBTENER JUEGOS (Para el buscador)
app.get("/items", async (req, res) => {
    try {
        const juegos = await Juego.find();
        res.json(juegos);
    } catch (error) {
        res.status(500).json({ error: "Error al obtener juegos" });
    }
});

// 4. RUTA PARA PUBLICAR JUEGOS (Desde el panel de colaborador)
app.post("/items/add", async (req, res) => {
    try {
        const { title, description, link, image } = req.body;

        // Verificar si el juego ya existe por título
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
        res.status(201).json({ ok: true, message: "Juego guardado para siempre en la nube." });
    } catch (error) {
        res.status(500).json({ error: "Error al guardar en el servidor." });
    }
});

// 5. INICIAR SERVIDOR
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Servidor UpGames corriendo en puerto ${PORT}`);
});
