const express = require("express")
const cors = require("cors")

const app = express()
const PORT = process.env.PORT || 3000

app.use(cors())
app.use(express.json())

// "Base de datos" en memoria
let items = []

// 1. ENVIAR datos (GET)
app.get("/items", (req, res) => {
  res.json(items)
})

// 2. RECIBIR UN SOLO ITEM (POST mejorado para usuarios)
app.post("/items/add", (req, res) => {
  const nuevoJuego = {
    id: Date.now(), // Genera un ID único basado en el tiempo
    status: "pendiente", // Todos entran para revisión
    ...req.body // Trae title, description, link, image
  }
  
  // Evitar duplicados por título
  const existe = items.some(i => i.title.toLowerCase() === nuevoJuego.title.toLowerCase())
  
  if (existe) {
    return res.status(400).json({ error: "El juego ya existe" })
  }

  items.push(nuevoJuego) // Añade al final sin borrar lo anterior
  res.json({ ok: true, message: "Esperando aprobación del admin" })
})

// 3. APROBAR UN JUEGO (PUT) - Solo para tu Panel Admin
app.put("/items/approve/:id", (req, res) => {
  const { id } = req.params
  const juego = items.find(i => i.id == id)
  if (juego) {
    juego.status = "aprobado"
    res.json({ ok: true })
  } else {
    res.status(404).json({ error: "No encontrado" })
  }
})

// 4. ELIMINAR UN JUEGO (DELETE) - Solo para tu Panel Admin
app.delete("/items/:id", (req, res) => {
  const { id } = req.params
  items = items.filter(i => i.id != id)
  res.json({ ok: true })
})

// MANTENER para compatibilidad (Opcional por si usas el viejo método)
app.post("/items", (req, res) => {
  items = req.body
  res.json({ ok: true })
})

app.listen(PORT, () => {
  console.log("Backend profesional corriendo en puerto", PORT)
})
