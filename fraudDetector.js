/**
 * ⚠️ SISTEMA DE DETECCIÓN AUTOMÁTICA DE FRAUDE
 * Detecta comportamientos sospechosos y marca usuarios para revisión admin
 */

const mongoose = require('mongoose');

// ========== CONFIGURACIÓN DE UMBRALES ==========
const THRESHOLDS = {
    // Descargas sospechosas
    MAX_DOWNLOADS_PER_MINUTE: 10,        // Máx descargas efectivas por minuto
    MAX_DOWNLOADS_PER_HOUR: 100,         // Máx descargas efectivas por hora
    MAX_DOWNLOADS_PER_DAY: 500,          // Máx descargas efectivas por día
    
    // Comportamiento de IP
    MAX_IPS_PER_USER_PER_HOUR: 5,        // Cambios de IP sospechosos (VPN hopping)
    MAX_DOWNLOADS_FROM_SINGLE_IP: 50,    // Descargas desde una sola IP (bot)
    
    // Velocidad anormal
    MIN_SECONDS_BETWEEN_DOWNLOADS: 3,    // Tiempo mínimo entre descargas del mismo usuario
    
    // Ganancia sospechosa
    MAX_EARNINGS_PER_HOUR: 0.50,         // Máx $0.50 USD por hora (500 descargas/hora)
};

// ========== SCHEMA: Registro de Comportamiento Sospechoso ==========
const SuspiciousActivitySchema = new mongoose.Schema({
    usuario: {
        type: String,
        required: true,
        index: true
    },
    tipo: {
        type: String,
        enum: [
            'download_velocity',     // Descargas demasiado rápidas
            'ip_hopping',           // Cambio constante de IPs (VPN)
            'single_ip_abuse',      // Muchas descargas desde una IP
            'bot_pattern',          // Patrón de bot detectado
            'earnings_spike',       // Aumento anormal de ganancias
            'time_anomaly'          // Tiempo entre descargas sospechoso
        ],
        required: true
    },
    severidad: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    detalles: {
        type: Object,
        default: {}
    },
    autoMarcado: {
        type: Boolean,
        default: false  // true si fue marcado automáticamente a lista negra
    },
    revisado: {
        type: Boolean,
        default: false
    },
    notasAdmin: {
        type: String,
        default: ''
    },
    fecha: {
        type: Date,
        default: Date.now,
        index: true
    }
}, {
    collection: 'suspicious_activities',
    timestamps: true
});

const SuspiciousActivity = mongoose.model('SuspiciousActivity', SuspiciousActivitySchema);

// ========== SCHEMA: Tracking de Actividad de Descarga (Cache temporal) ==========
const DownloadTrackingSchema = new mongoose.Schema({
    usuario: {
        type: String,
        required: true,
        index: true
    },
    juegoId: {
        type: String,
        required: true
    },
    ip: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true,
        expires: 86400 // Se auto-elimina después de 24 horas (TTL index)
    },
    ganancia: {
        type: Number,
        default: 0
    }
}, {
    collection: 'download_tracking',
    timestamps: false
});

const DownloadTracking = mongoose.model('DownloadTracking', DownloadTrackingSchema);

// ========== FUNCIONES DE DETECCIÓN ==========

/**
 * Analiza el comportamiento del usuario y detecta anomalías
 * @param {String} usuario - Nombre de usuario
 * @param {String} juegoId - ID del juego descargado
 * @param {String} ip - IP del usuario
 * @param {Number} ganancia - Ganancia generada en esta descarga
 * @returns {Object} - { suspicious: boolean, reasons: [], severity: string, autoFlag: boolean }
 */
async function analyzeDownloadBehavior(usuario, juegoId, ip, ganancia = 0) {
    const now = new Date();
    const reasons = [];
    let maxSeverity = 'low';
    let autoFlag = false; // Si es true, se marca automáticamente a lista negra

    try {
        // ========== 1. REGISTRAR ESTA DESCARGA ==========
        await DownloadTracking.create({
            usuario,
            juegoId,
            ip,
            timestamp: now,
            ganancia
        });

        // ========== 2. OBTENER ACTIVIDAD RECIENTE ==========
        const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        // Descargas del usuario en diferentes períodos
        const downloadsLastMinute = await DownloadTracking.countDocuments({
            usuario,
            timestamp: { $gte: oneMinuteAgo }
        });

        const downloadsLastHour = await DownloadTracking.countDocuments({
            usuario,
            timestamp: { $gte: oneHourAgo }
        });

        const downloadsLastDay = await DownloadTracking.countDocuments({
            usuario,
            timestamp: { $gte: oneDayAgo }
        });

        // ========== 3. DETECCIÓN: VELOCIDAD DE DESCARGA ANORMAL ==========
        if (downloadsLastMinute > THRESHOLDS.MAX_DOWNLOADS_PER_MINUTE) {
            reasons.push({
                tipo: 'download_velocity',
                mensaje: `${downloadsLastMinute} descargas en 1 minuto (máx: ${THRESHOLDS.MAX_DOWNLOADS_PER_MINUTE})`,
                valor: downloadsLastMinute
            });
            maxSeverity = 'critical';
            autoFlag = true; // Auto-marcar por velocidad extrema
        }

        if (downloadsLastHour > THRESHOLDS.MAX_DOWNLOADS_PER_HOUR) {
            reasons.push({
                tipo: 'download_velocity',
                mensaje: `${downloadsLastHour} descargas en 1 hora (máx: ${THRESHOLDS.MAX_DOWNLOADS_PER_HOUR})`,
                valor: downloadsLastHour
            });
            maxSeverity = upgradeSeverity(maxSeverity, 'high');
            autoFlag = true;
        }

        if (downloadsLastDay > THRESHOLDS.MAX_DOWNLOADS_PER_DAY) {
            reasons.push({
                tipo: 'download_velocity',
                mensaje: `${downloadsLastDay} descargas en 24 horas (máx: ${THRESHOLDS.MAX_DOWNLOADS_PER_DAY})`,
                valor: downloadsLastDay
            });
            maxSeverity = upgradeSeverity(maxSeverity, 'medium');
        }

        // ========== 4. DETECCIÓN: IP HOPPING (VPN/Proxy) ==========
        const uniqueIPsLastHour = await DownloadTracking.distinct('ip', {
            usuario,
            timestamp: { $gte: oneHourAgo }
        });

        if (uniqueIPsLastHour.length > THRESHOLDS.MAX_IPS_PER_USER_PER_HOUR) {
            reasons.push({
                tipo: 'ip_hopping',
                mensaje: `${uniqueIPsLastHour.length} IPs diferentes en 1 hora (posible VPN hopping)`,
                valor: uniqueIPsLastHour.length,
                ips: uniqueIPsLastHour
            });
            maxSeverity = upgradeSeverity(maxSeverity, 'high');
            autoFlag = true;
        }

        // ========== 5. DETECCIÓN: ABUSO DESDE UNA SOLA IP ==========
        const downloadsFromThisIP = await DownloadTracking.countDocuments({
            ip,
            timestamp: { $gte: oneDayAgo }
        });

        if (downloadsFromThisIP > THRESHOLDS.MAX_DOWNLOADS_FROM_SINGLE_IP) {
            reasons.push({
                tipo: 'single_ip_abuse',
                mensaje: `${downloadsFromThisIP} descargas desde IP ${ip} en 24h (posible bot)`,
                valor: downloadsFromThisIP,
                ip
            });
            maxSeverity = upgradeSeverity(maxSeverity, 'high');
            autoFlag = true;
        }

        // ========== 6. DETECCIÓN: TIEMPO ENTRE DESCARGAS SOSPECHOSO ==========
        const lastDownloads = await DownloadTracking.find({
            usuario,
            timestamp: { $gte: oneHourAgo }
        }).sort({ timestamp: -1 }).limit(5);

        if (lastDownloads.length >= 2) {
            let hasAnomalousSpeed = false;
            for (let i = 0; i < lastDownloads.length - 1; i++) {
                const timeDiff = (lastDownloads[i].timestamp - lastDownloads[i + 1].timestamp) / 1000; // en segundos
                if (timeDiff < THRESHOLDS.MIN_SECONDS_BETWEEN_DOWNLOADS) {
                    hasAnomalousSpeed = true;
                    break;
                }
            }

            if (hasAnomalousSpeed) {
                reasons.push({
                    tipo: 'time_anomaly',
                    mensaje: `Descargas con menos de ${THRESHOLDS.MIN_SECONDS_BETWEEN_DOWNLOADS}s de diferencia (patrón de bot)`,
                    valor: THRESHOLDS.MIN_SECONDS_BETWEEN_DOWNLOADS
                });
                maxSeverity = upgradeSeverity(maxSeverity, 'high');
            }
        }

        // ========== 7. DETECCIÓN: SPIKE DE GANANCIAS ==========
        const earningsLastHour = await DownloadTracking.aggregate([
            {
                $match: {
                    usuario,
                    timestamp: { $gte: oneHourAgo }
                }
            },
            {
                $group: {
                    _id: null,
                    total: { $sum: '$ganancia' }
                }
            }
        ]);

        const totalEarnings = earningsLastHour.length > 0 ? earningsLastHour[0].total : 0;

        if (totalEarnings > THRESHOLDS.MAX_EARNINGS_PER_HOUR) {
            reasons.push({
                tipo: 'earnings_spike',
                mensaje: `$${totalEarnings.toFixed(2)} ganados en 1 hora (máx: $${THRESHOLDS.MAX_EARNINGS_PER_HOUR})`,
                valor: totalEarnings
            });
            maxSeverity = upgradeSeverity(maxSeverity, 'critical');
            autoFlag = true;
        }

        // ========== 8. REGISTRAR ACTIVIDAD SOSPECHOSA SI SE DETECTÓ ==========
        if (reasons.length > 0) {
            // Crear un registro por cada tipo de razón detectada
            for (const reason of reasons) {
                await SuspiciousActivity.create({
                    usuario,
                    tipo: reason.tipo,
                    severidad: maxSeverity,
                    detalles: {
                        mensaje: reason.mensaje,
                        valor: reason.valor,
                        juegoId,
                        ip,
                        timestamp: now,
                        ...reason
                    },
                    autoMarcado: autoFlag,
                    revisado: false
                });
            }

            console.log(`⚠️ FRAUDE DETECTADO - Usuario: @${usuario}, Severidad: ${maxSeverity.toUpperCase()}, Razones: ${reasons.length}`);
            
            return {
                suspicious: true,
                reasons: reasons.map(r => r.mensaje),
                severity: maxSeverity,
                autoFlag,
                details: reasons
            };
        }

        return {
            suspicious: false,
            reasons: [],
            severity: 'none',
            autoFlag: false,
            details: []
        };

    } catch (error) {
        console.error('❌ Error en análisis de comportamiento:', error);
        return {
            suspicious: false,
            reasons: ['Error en análisis'],
            severity: 'none',
            autoFlag: false,
            error: error.message
        };
    }
}

/**
 * Marca automáticamente un usuario en lista negra
 * @param {Object} Usuario - Modelo de Usuario de Mongoose
 * @param {String} usuario - Nombre de usuario
 * @param {String} razon - Razón de la marcación
 */
async function autoFlagUser(Usuario, usuario, razon) {
    try {
        const user = await Usuario.findOne({ usuario });
        if (!user) {
            console.error(`❌ Usuario no encontrado para auto-flag: @${usuario}`);
            return false;
        }

        // Solo marcar si no está ya en lista negra
        if (!user.listaNegraAdmin) {
            user.listaNegraAdmin = true;
            user.fechaListaNegra = new Date();
            user.notasAdmin = (user.notasAdmin || '') + 
                `\n[AUTO-DETECCIÓN ${new Date().toLocaleString('es-ES')}]: ${razon}`;
            
            await user.save();
            
            console.log(`🚫 Usuario auto-marcado en lista negra: @${usuario} - Razón: ${razon}`);
            return true;
        } else {
            console.log(`ℹ️ Usuario ya está en lista negra: @${usuario}`);
            return false;
        }
    } catch (error) {
        console.error('❌ Error al auto-marcar usuario:', error);
        return false;
    }
}

/**
 * Obtiene estadísticas de actividad sospechosa
 */
async function getSuspiciousStats() {
    try {
        const [
            totalSuspicious,
            pendingReview,
            autoFlagged,
            bySeverity,
            byType,
            recentActivity
        ] = await Promise.all([
            SuspiciousActivity.countDocuments(),
            SuspiciousActivity.countDocuments({ revisado: false }),
            SuspiciousActivity.countDocuments({ autoMarcado: true }),
            SuspiciousActivity.aggregate([
                { $group: { _id: '$severidad', count: { $sum: 1 } } }
            ]),
            SuspiciousActivity.aggregate([
                { $group: { _id: '$tipo', count: { $sum: 1 } } }
            ]),
            SuspiciousActivity.find({ revisado: false })
                .sort({ fecha: -1 })
                .limit(10)
        ]);

        return {
            total: totalSuspicious,
            pendingReview,
            autoFlagged,
            bySeverity: Object.fromEntries(bySeverity.map(x => [x._id, x.count])),
            byType: Object.fromEntries(byType.map(x => [x._id, x.count])),
            recentActivity
        };
    } catch (error) {
        console.error('❌ Error obteniendo stats de fraude:', error);
        return null;
    }
}

/**
 * Helper: Upgrade severity level
 */
function upgradeSeverity(current, newLevel) {
    const levels = { low: 1, medium: 2, high: 3, critical: 4 };
    return levels[newLevel] > levels[current] ? newLevel : current;
}

module.exports = {
    analyzeDownloadBehavior,
    autoFlagUser,
    getSuspiciousStats,
    SuspiciousActivity,
    DownloadTracking,
    THRESHOLDS
};
