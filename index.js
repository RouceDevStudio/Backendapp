const express = require("express")
const cors = require("cors")

const app = express()
const PORT = process.env.PORT || 3000

// Middlewares
app.use(cors())
app.use(express.json())

// "Base de datos" en memoria
let items = []

// RECIBIR datos desde el frontend (POST)
app.post("/items", (req, res) => {
  items = req.body
  res.json({ ok: true })
})

// ENVIAR datos al frontend (GET)
app.get("/items", (req, res) => {
  res.json(items)
})

// Arrancar servidor (NO CAMBIAR NADA AQUÍ)
app.listen(PORT, () => {
  console.log("Backend corriendo en puerto", PORT)
})