const mongoose = require('mongoose');

// Tu URL verificada y lista para conectar
const uri = "mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri)
  .then(() => {
    console.log("🚀 ¡CONEXIÓN EXITOSA! UpGames ya tiene base de datos eterna.");
  })
  .catch(err => {
    console.error("❌ Error al conectar a MongoDB:", err);
  });


const API_URL = "https://backendapp-037y.onrender.com";

// Referencias a los inputs
const addTitle = document.getElementById("addTitle");
const addDescription = document.getElementById("addDescription");
const addLink = document.getElementById("addLink");
const addImage = document.getElementById("addImage");
const btnPublicar = document.getElementById("publicarBtn"); // Asegúrate que el ID coincida en tu HTML

// FUNCIÓN PRINCIPAL PARA PUBLICAR
async function publicarJuego() {
    // 1. Recoger los valores
    const nuevoJuego = {
        title: addTitle.value.trim(),
        description: addDescription.value.trim(),
        link: addLink.value.trim(),
        image: addImage.value.trim()
    };

    // 2. Validación básica en el cliente
    if (!nuevoJuego.title || !nuevoJuego.link) {
        alert("Por favor, rellena al menos el Título y el Enlace de descarga.");
        return;
    }

    try {
        // 3. Enviar al servidor usando la nueva ruta /items/add
        const response = await fetch(`${API_URL}/items/add`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(nuevoJuego)
        });

        const data = await response.json();

        if (response.ok) {
            alert("🚀 ¡Juego enviado! Ahora está en revisión por el administrador.");
            // Limpiar el formulario
            addTitle.value = "";
            addDescription.value = "";
            addLink.value = "";
            addImage.value = "";
        } else {
            // Aquí capturamos el error de "El juego ya existe" que configuramos en el backend
            alert("Error: " + (data.error || "No se pudo publicar el juego."));
        }

    } catch (error) {
        console.error("Error en la conexión:", error);
        alert("Hubo un fallo al conectar con el servidor.");
    }
}

// Escuchar el evento del botón
if (btnPublicar) {
    btnPublicar.addEventListener("click", publicarJuego);
}
