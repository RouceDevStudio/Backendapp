const express = require("express")
const cors = require("cors")

const app = express()
const PORT = process.env.PORT || 3000

app.use(cors())
app.use(express.json())

// "base de datos" temporal
let data = []

// RECIBIR info (front input)
app.post("/items", (req, res) => {
  const item = req.body
  data.push(item)

  res.json({
    ok: true,
    message: "Dato recibido y guardado"
  })
})

// ENVIAR info (front output)
app.get("/items", (req, res) => {
  res.json(data)
})

app.listen(PORT, () => {
  console.log("Backend corriendo en puerto", PORT)
})
