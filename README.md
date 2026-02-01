# UpGames Backend API v2.0

Backend robusto y seguro para la plataforma UpGames.

## 🚀 Características

- ✅ **Autenticación JWT** con bcrypt para contraseñas
- 🛡️ **Seguridad**: Helmet, CORS configurado, Rate Limiting
- 📊 **Validación de datos** con express-validator
- 🔄 **Sistema de seguimiento** entre usuarios
- ⭐ **Favoritos** y comentarios
- 🎮 **Gestión de juegos** con aprobación
- 📈 **Verificación automática** por seguidores

## 📋 Requisitos Previos

- Node.js >= 18.0.0
- Cuenta de MongoDB Atlas
- Cuenta de Render (o similar para hosting)

## 🛠️ Instalación Local

1. **Clonar el repositorio**
```bash
git clone <tu-repo>
cd upgames-backend
```

2. **Instalar dependencias**
```bash
npm install
```

3. **Configurar variables de entorno**
```bash
cp .env.example .env
```

Edita `.env` con tus credenciales:
```
MONGODB_URI=tu_uri_de_mongodb
JWT_SECRET=tu_secreto_super_seguro
PORT=10000
NODE_ENV=development
```

4. **Iniciar en desarrollo**
```bash
npm run dev
```

## 🌐 Deploy en Render

### Paso 1: Preparar el repositorio
Sube tu código a GitHub/GitLab con estos archivos:
- `index.js`
- `package.json`
- `.env.example` (NO subas el .env real)

### Paso 2: Crear Web Service en Render

1. Ve a [render.com](https://render.com)
2. Click en "New +" → "Web Service"
3. Conecta tu repositorio
4. Configura:
   - **Name**: upgames-backend (o el que prefieras)
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free

### Paso 3: Variables de Entorno

En Render, ve a "Environment" y agrega:

```
MONGODB_URI=mongodb+srv://adminupgames2026:78simon87@cluster0.turx6r1.mongodb.net/UpGames?retryWrites=true&w=majority
JWT_SECRET=upgames_production_secret_2026_muy_seguro
NODE_ENV=production
```

⚠️ **IMPORTANTE**: Cambia `JWT_SECRET` por un valor aleatorio y seguro.

### Paso 4: Deploy

1. Click en "Create Web Service"
2. Espera que termine el deploy (2-5 minutos)
3. Tu API estará en: `https://tu-nombre-app.onrender.com`

## 🔧 Solución de Problemas Comunes

### Error: "Cannot find module 'dotenv'"
**Solución**: Asegúrate de que `package.json` tiene todas las dependencias y ejecuta `npm install`

### Error: "MongoDB connection failed"
**Solución**: 
- Verifica que `MONGODB_URI` esté correctamente configurada
- Asegura que tu IP esté en la whitelist de MongoDB Atlas (0.0.0.0/0 para permitir todas)

### Error: "Port already in use"
**Solución**: Cambia el puerto en `.env` o mata el proceso:
```bash
# Linux/Mac
lsof -ti:10000 | xargs kill -9

# Windows
netstat -ano | findstr :10000
taskkill /PID <pid> /F
```

### Deploy en Render falla
**Solución**:
1. Revisa los logs en Render Dashboard
2. Asegúrate de que `"start": "node index.js"` esté en package.json
3. Verifica que Node.js sea >= 18 en Render settings

## 📡 Endpoints Principales

### Autenticación
- `POST /auth/register` - Registro
- `POST /auth/login` - Login
- `GET /auth/users` - Listar usuarios

### Juegos/Items
- `GET /items` - Obtener todos
- `POST /items/add` - Agregar nuevo
- `PUT /items/approve/:id` - Aprobar
- `DELETE /items/:id` - Eliminar

### Social
- `PUT /auth/follow/:usuario` - Seguir/Dejar de seguir
- `POST /favoritos/add` - Agregar favorito
- `GET /favoritos/:usuario` - Ver favoritos

### Utilidades
- `GET /health` - Estado del servidor
- `GET /search?q=termino` - Búsqueda global

## 🔐 Seguridad Implementada

- ✅ Contraseñas hasheadas con bcrypt
- ✅ Tokens JWT para sesiones
- ✅ Rate limiting para prevenir ataques
- ✅ Validación de datos con express-validator
- ✅ Helmet para headers de seguridad
- ✅ CORS configurado
- ✅ Sanitización de inputs

## 🆕 Diferencias con la Versión Anterior

### Mejoras
1. **JWT Authentication** - Sistema de tokens más seguro
2. **Bcrypt** - Contraseñas hasheadas (no en texto plano)
3. **Rate Limiting** - Protección contra spam/ataques
4. **Validación robusta** - Todos los endpoints validados
5. **Mejor manejo de errores** - Respuestas consistentes
6. **Sistema de "siguiendo"** - Bidireccional ahora

### Compatibilidad
- ✅ Mantiene compatibilidad con frontend existente
- ✅ Mismos endpoints principales
- ✅ Respuestas similares (con campos adicionales)
- ⚠️ Login ahora retorna `token` - actualizar frontend para guardarlo

## 📝 Migración desde Versión Anterior

### Para usuarios existentes:

Las contraseñas antiguas (sin hash) seguirán funcionando, pero se recomienda:

1. **Opcional**: Crear endpoint de migración para re-hashear contraseñas
2. **O**: Los usuarios pueden cambiar su contraseña para que se hashee automáticamente

### Para el frontend:

Actualizar las llamadas de login para guardar el token:

```javascript
// Antes
localStorage.setItem("user_admin", data.usuario);

// Ahora (AÑADIR)
localStorage.setItem("user_admin", data.usuario);
localStorage.setItem("auth_token", data.token); // Nuevo
```

Y enviar el token en las peticiones protegidas:
```javascript
fetch(API_URL + "/ruta-protegida", {
    headers: {
        'Authorization': `Bearer ${localStorage.getItem("auth_token")}`
    }
});
```

## 🤝 Contribuir

1. Fork el proyecto
2. Crea tu rama (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add: amazing feature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

MIT License - Ver archivo LICENSE para más detalles

## 👨‍💻 Autor

**RouceDev Studio**
- GitHub: [@roucedevstudio](https://github.com/roucedevstudio)

---

⭐ Si te gusta este proyecto, dale una estrella en GitHub!
