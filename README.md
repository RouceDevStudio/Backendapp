# 🎮 UpGames Backend v3.1.0

Backend API completo para UpGames - Plataforma de juegos con sistema de economía CPM, detección de fraude y panel administrativo.

## 🚀 Características Principales

### ✨ Sistema Económico CPM
- **CPM de $2.00** por cada 1,000 descargas efectivas
- **50% de ganancia** para el creador del juego
- Umbral mínimo de **2,000 descargas** antes de generar ingresos
- Retiro mínimo de **$10 USD**
- Control de **2 descargas máximas por IP por día** (anti-bots)

### 🤖 6 JOBS AUTOMÁTICOS (CRON JOBS)
1. **Auto-Ping (cada 14 min)** - Evita que Render duerma el servidor
2. **Limpieza de Comentarios (cada 24h)** - Elimina vacíos y duplicados
3. **Reset de Reportes (cada 12h)** - Resetea reportes de links online antiguos
4. **Auto-Rechazo (cada 24h)** - Rechaza items pendientes de +7 días
5. **Auto-Marcar Caídos (cada 6h)** - Marca links con +10 reportes y 72h sin revisión
6. **Auto-Verificación (cada 6h)** - Asigna niveles por seguidores (100/500/1000+)

### 🛡️ Detección Automática de Fraude
- **6 tipos de fraude** detectados automáticamente:
  - Velocidad anormal de descargas
  - IP hopping (VPN abuse)
  - Abuso desde una sola IP
  - Patrones de bots
  - Picos sospechosos de ganancias
  - Tiempo entre descargas anormal
- **Auto-bloqueo** de usuarios sospechosos
- Panel de admin para revisar actividades

### 📊 Panel de Administración Completo
- Gestión de usuarios (verificación, lista negra, ajustes de saldo)
- Gestión de juegos (aprobar, rechazar, marcar links caídos)
- Sistema de pagos (solicitudes, procesamiento, historial)
- Estadísticas en tiempo real
- Monitoreo de fraude

### 🔐 Seguridad
- Rate limiting granular por endpoint
- JWT con refresh tokens
- Helmet.js para headers de seguridad
- CORS configurado
- Validación de inputs con express-validator
- Logs profesionales con Winston

## 📋 Requisitos

- Node.js >= 18.0.0
- MongoDB (Atlas recomendado)
- Cuenta de PayPal (para pagos a creadores)

## 🛠️ Instalación

### 1. Clonar el proyecto
```bash
git clone <tu-repo>
cd backend-optimizado
```

### 2. Instalar dependencias
```bash
npm install
```

### 3. Configurar variables de entorno
```bash
cp .env.example .env
```

Edita el archivo `.env` con tus valores:
```env
MONGODB_URI=mongodb+srv://usuario:password@cluster.mongodb.net/upgames
JWT_SECRET=tu_secret_super_seguro
JWT_REFRESH_SECRET=otro_secret_diferente
NODE_ENV=production
PORT=10000
```

### 4. Iniciar el servidor

**Desarrollo:**
```bash
npm run dev
```

**Producción:**
```bash
npm start
```

## 📡 Endpoints Principales

### 🔐 Autenticación
```
POST   /auth/register          - Registrar usuario
POST   /auth/login             - Iniciar sesión
GET    /auth/users             - Listar usuarios
```

### 💰 Economía (Usuario)
```
POST   /economia/validar-descarga      - Validar y contar descarga
POST   /economia/solicitar-pago        - Solicitar retiro ($10 min)
GET    /economia/mi-saldo              - Consultar saldo y stats
PUT    /economia/actualizar-paypal     - Configurar email PayPal
```

### 📦 Items/Juegos
```
GET    /items                  - Listar juegos aprobados
GET    /items/:id              - Obtener juego específico
GET    /items/user/:usuario    - Juegos de un usuario
POST   /items/add              - Agregar nuevo juego
PUT    /items/report/:id       - Reportar link caído
DELETE /items/:id              - Eliminar juego
```

### 👥 Usuarios Públicos
```
GET    /usuarios/perfil-publico/:usuario       - Ver perfil público
PUT    /usuarios/toggle-seguir/:actual/:objetivo - Seguir/dejar de seguir
PUT    /usuarios/update-avatar                 - Actualizar avatar
PUT    /usuarios/update-bio                    - Actualizar biografía
GET    /usuarios/stats-seguimiento/:usuario    - Stats de seguidores
```

### 💬 Comentarios
```
GET    /comentarios/:itemId    - Comentarios de un item
POST   /comentarios            - Agregar comentario
DELETE /comentarios/:id        - Eliminar comentario
```

### ⭐ Favoritos
```
POST   /favoritos/add          - Agregar a favoritos
DELETE /favoritos/remove       - Quitar de favoritos
GET    /favoritos/:usuario     - Listar favoritos
```

### 🔧 Admin - Finanzas
```
GET    /admin/finanzas/solicitudes-pendientes  - Solicitudes de pago
POST   /admin/finanzas/procesar-pago/:id       - Aprobar pago
POST   /admin/finanzas/rechazar-pago/:id       - Rechazar pago
GET    /admin/finanzas/historial               - Historial de pagos
GET    /admin/finanzas/estadisticas            - Stats financieras
GET    /admin/payments-pending                 - Usuarios elegibles
```

### 🔧 Admin - Usuarios
```
GET    /admin/users/detalle/:id           - Detalle completo
PUT    /admin/users/lista-negra/:id       - Agregar/quitar lista negra
PUT    /admin/users/notas/:id             - Agregar notas admin
PUT    /admin/users/ajustar-saldo/:id     - Ajustar saldo manualmente
DELETE /admin/users/:id/items             - Eliminar todos sus items
PUT    /admin/users/:id/reset-saldo       - Resetear saldo
GET    /admin/users/lista-negra           - Listar usuarios bloqueados
```

### 🔧 Admin - Items
```
GET    /admin/items                       - Listar todos los items
PUT    /admin/items/:id                   - Actualizar item
PUT    /admin/items/bulk-action           - Acciones en lote
PUT    /admin/items/:id/reset-reports     - Resetear reportes
PUT    /admin/items/:id/link-status       - Cambiar estado link
GET    /admin/links/en-revision           - Links reportados
PUT    /admin/links/marcar-caido/:id      - Marcar como caído
```

### 🔧 Admin - Estadísticas
```
GET    /admin/stats/dashboard             - Dashboard general
GET    /admin/stats/top-usuarios          - Top 20 por descargas
```

### 🚨 Admin - Detección de Fraude
```
GET    /admin/fraud/suspicious-activities - Actividades sospechosas
PUT    /admin/fraud/mark-reviewed/:id     - Marcar como revisado
GET    /admin/fraud/user-history/:usuario - Historial de fraude
```

### 🏥 Sistema
```
GET    /health                - Healthcheck del servidor
GET    /api/version           - Versión de la API
GET    /                      - Info general
```

## 🎯 Flujo de Descarga y Ganancia

1. Usuario hace clic en "Descargar juego"
2. Frontend llama a `POST /economia/validar-descarga`
3. Backend verifica:
   - ✅ Juego existe y está aprobado
   - ✅ IP no ha excedido límite diario (2/día)
   - ✅ Incrementa contador de descargas efectivas
   - ✅ Si autor está en lista negra → NO genera ganancia
   - ✅ Si descargas > 2,000 y autor verificado:
     - 💰 Calcula ganancia: `($2.00 * 0.50) / 1000 = $0.001 por descarga`
     - 🔍 Ejecuta análisis de fraude
     - 🚫 Si fraude crítico → auto-bloquea y revierte ganancia
   - ✅ Actualiza saldo del autor
4. Devuelve link de descarga

## 🛡️ Sistema de Detección de Fraude

### Umbrales de Detección
```javascript
MAX_DOWNLOADS_PER_MINUTE: 10
MAX_DOWNLOADS_PER_HOUR: 100
MAX_DOWNLOADS_PER_DAY: 500
MAX_IPS_PER_USER_PER_HOUR: 5
MAX_DOWNLOADS_FROM_SINGLE_IP: 50
MIN_SECONDS_BETWEEN_DOWNLOADS: 3
MAX_EARNINGS_PER_HOUR: $0.50
```

### Niveles de Severidad
- **Low** - Advertencia
- **Medium** - Requiere revisión
- **High** - Sospechoso
- **Critical** - Auto-bloqueo automático

### ¿Qué pasa cuando se detecta fraude?
1. Se registra la actividad sospechosa en la base de datos
2. Si severidad es **critical** o **high** con auto-flag:
   - Usuario se marca automáticamente en lista negra
   - Se revierte la ganancia de esa descarga
   - Se agrega nota automática en el perfil
3. Admin puede revisar en `/admin/fraud/suspicious-activities`

## 📊 Schemas de Base de Datos

### Usuario
```javascript
{
  usuario: String (único),
  email: String (único),
  password: String (hasheado),
  paypalEmail: String,
  saldo: Number,
  descargasTotales: Number,
  isVerificado: Boolean,
  verificadoNivel: Number (0-3),
  listaNegraAdmin: Boolean,
  notasAdmin: String,
  avatar: String,
  bio: String,
  listaSeguidores: [String],
  siguiendo: [String]
}
```

### Juego
```javascript
{
  usuario: String,
  title: String,
  description: String,
  image: String,
  link: String,
  status: String (pendiente|aprobado|rechazado),
  linkStatus: String (online|revision|caido),
  reportes: Number,
  category: String,
  tags: [String],
  descargasEfectivas: Number
}
```

### Pago
```javascript
{
  usuario: String,
  monto: Number,
  paypalEmail: String,
  estado: String (pendiente|procesado|completado|rechazado),
  notas: String,
  fecha: Date
}
```

### DescargaIP (TTL 24h)
```javascript
{
  juegoId: ObjectId,
  ip: String,
  contadorHoy: Number,
  fecha: Date (auto-elimina después de 24h)
}
```

### SuspiciousActivity
```javascript
{
  usuario: String,
  tipo: String,
  severidad: String,
  detalles: Object,
  autoMarcado: Boolean,
  revisado: Boolean,
  notasAdmin: String,
  fecha: Date
}
```

## 🔧 Configuración Avanzada

### config.js
Todos los valores configurables están centralizados en `config.js`:

```javascript
CPM_VALUE: 2.00                    // $2 por 1,000 descargas
AUTHOR_PERCENTAGE: 0.50            // 50% para el creador
MIN_DOWNLOADS_TO_EARN: 2000        // Umbral mínimo
MIN_WITHDRAWAL: 10                 // Retiro mínimo $10
MAX_DOWNLOADS_PER_IP_PER_DAY: 2    // Límite anti-bots
```

### Habilitar/Deshabilitar Features
```javascript
FEATURES: {
    ENABLE_FRAUD_DETECTION: true,
    ENABLE_AUTO_PAYMENTS: false,        // PayPal API
    ENABLE_EMAIL_NOTIFICATIONS: false   // SendGrid/Nodemailer
}
```

## 🚀 Despliegue en Producción

### Render.com (Recomendado)
1. Conecta tu repositorio de GitHub
2. Configura las variables de entorno
3. Build Command: `npm install`
4. Start Command: `npm start`

### Variables de Entorno Requeridas
```
MONGODB_URI=mongodb+srv://...
JWT_SECRET=...
JWT_REFRESH_SECRET=...
NODE_ENV=production
PORT=10000
```

### Heroku
```bash
heroku create upgames-backend
heroku config:set MONGODB_URI=...
heroku config:set JWT_SECRET=...
git push heroku main
```

## 📈 Monitoreo y Logs

### Winston Logger
Logs estructurados en `logs/app.log`:
```
✅ [GET] /items - 200 (45ms)
❌ [POST] /economia/validar-descarga - 404 (12ms)
💰 Ganancia generada - Autor: @usuario, +$0.0010 USD
🚫 Usuario auto-marcado - @fraudster
```

### Healthcheck
```bash
curl https://tu-backend.com/health
```

## 🐛 Debugging

### Logs en desarrollo
```bash
npm run dev
```

### Verificar MongoDB
```javascript
// En la consola de MongoDB
use upgames
db.usuarios.find().pretty()
db.juegos.find({ status: 'aprobado' }).count()
```

## ❓ FAQ

**Q: ¿Cómo cambio el CPM o el porcentaje del autor?**  
A: Edita `config.js` y cambia `CPM_VALUE` y `AUTHOR_PERCENTAGE`

**Q: ¿Cómo agrego un admin?**  
A: Actualiza manualmente en MongoDB: `db.usuarios.updateOne({usuario: "admin"}, {$set: {verificadoNivel: 3}})`

**Q: ¿Los endpoints de admin requieren autenticación?**  
A: No, según tu solicitud. Para agregar auth, usa el middleware `verificarToken` en cada ruta admin.

**Q: ¿Puedo desactivar la detección de fraude?**  
A: Sí, en `config.js` cambia `ENABLE_FRAUD_DETECTION: false`

**Q: ¿Cómo proceso pagos reales de PayPal?**  
A: Necesitas integrar la PayPal API. Por ahora el sistema solo crea solicitudes que debes procesar manualmente.

## 📝 Changelog

### v3.1.0 (Actual)
- ✅ Sistema económico CPM completo
- ✅ Detección automática de fraude
- ✅ Panel admin de finanzas
- ✅ Sistema de pagos
- ✅ Gestión de lista negra
- ✅ 51 endpoints funcionales
- ✅ Logs profesionales con Winston
- ✅ Arquitectura modular

## 📄 Licencia

MIT License - Jhonatan David Castro Galviz (@RouceDev)

## 🤝 Contribuir

Pull requests son bienvenidos. Para cambios importantes, abre un issue primero.

## 📞 Soporte

Para reportar bugs o solicitar features, abre un issue en GitHub.

---

**Desarrollado con ❤️ por @RouceDev**
