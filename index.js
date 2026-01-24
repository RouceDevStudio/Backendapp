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

// ====================================================
// BLOQUE DE USUARIOS Y LÓGICA FINAL (REEMPLAZAR AL FINAL)
// ====================================================

// 1. Modelo de Usuario
const usuarioSchema = new mongoose.Schema({
    usuario: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fecha: { type: Date, default: Date.now }
});

const Usuario = mongoose.models.Usuario || mongoose.model("Usuario", usuarioSchema);

// 2. RUTA: Registro de nuevos colaboradores
app.post("/auth/register", async (req, res) => {
    try {
        const { usuario, password } = req.body;
        if (!usuario || !password) return res.status(400).json({ mensaje: "Faltan datos" });

        const existe = await Usuario.findOne({ usuario });
        if (existe) return res.status(400).json({ mensaje: "El usuario ya existe" });

        const nuevoUsuario = new Usuario({ usuario, password });
        await nuevoUsuario.save();
        res.status(201).json({ mensaje: "Perfil Cloud creado con éxito" });
    } catch (error) {
        res.status(500).json({ mensaje: "Error en registro", detalle: error.message });
    }
});

// 3. RUTA: Login
app.post("/auth/login", async (req, res) => {
    try {
        const { usuario, password } = req.body;
        const userEncontrado = await Usuario.findOne({ usuario, password });

        if (userEncontrado) {
            res.json({ success: true, usuario: userEncontrado.usuario });
        } else {
            res.status(401).json({ success: false, mensaje: "Usuario o clave incorrectos" });
        }
    } catch (error) {
        res.status(500).json({ mensaje: "Error de servidor" });
    }
});

// 4. RUTA PARA OBTENER SOLO MIS JUEGOS (Manejo de Perfil)
app.get("/items/my/:user", async (req, res) => {
    try {
        const misJuegos = await Juego.find({ usuario: req.params.user });
        res.json(misJuegos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 5. INICIO DEL SERVIDOR (SIEMPRE AL FINAL)
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Servidor Cloud Repository en puerto ${PORT}`);
});
