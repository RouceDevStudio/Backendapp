// ========================================
// ⚠️ SISTEMA DE DETECCIÓN DE FRAUDE OPTIMIZADO
// ========================================

const mongoose = require('mongoose');
const logger = require('./logger');

// ========== CONFIGURACIÓN DE UMBRALES ==========
const THRESHOLDS = {
    MAX_DOWNLOADS_PER_MINUTE: 10,
    MAX_DOWNLOADS_PER_HOUR: 100,
    MAX_DOWNLOADS_PER_DAY: 500,
    MAX_IPS_PER_USER_PER_HOUR: 5,
    MAX_DOWNLOADS_FROM_SINGLE_IP: 50,
    MIN_SECONDS_BETWEEN_DOWNLOADS: 3,
    MAX_EARNINGS_PER_HOUR: 0.50,
};

// ========== SCHEMAS ==========

const SuspiciousActivitySchema = new mongoose.Schema({
    usuario: { type: String, required: true, index: true },
    tipo: {
        type: String,
        enum: ['download_velocity', 'ip_hopping', 'single_ip_abuse', 'bot_pattern', 'earnings_spike', 'time_anomaly'],
        required: true
    },
    severidad: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'medium'
    },
    detalles: { type: Object, default: {} },
    autoMarcado: { type: Boolean, default: false },
    revisado: { type: Boolean, default: false },
    notasAdmin: { type: String, default: '' },
    fecha: { type: Date, default: Date.now, index: true }
}, {
    collection: 'suspicious_activities',
    timestamps: true
});

const DownloadTrackingSchema = new mongoose.Schema({
    usuario: { type: String, required: true, index: true },
    juegoId: { type: String, required: true },
    ip: { type: String, required: true, index: true },
    timestamp: { 
        type: Date, 
        default: Date.now, 
        index: true, 
        expires: 86400 
    },
    ganancia: { type: Number, default: 0 }
}, {
    collection: 'download_tracking',
    timestamps: false
});

const SuspiciousActivity = mongoose.model('SuspiciousActivity', SuspiciousActivitySchema);
const DownloadTracking = mongoose.model('DownloadTracking', DownloadTrackingSchema);

// ========== FUNCIÓN PRINCIPAL OPTIMIZADA ==========

/**
 * 🚀 VERSIÓN OPTIMIZADA: Una sola query de agregación
 * Analiza comportamiento del usuario y detecta anomalías
 */
async function analyzeDownloadBehavior(usuario, juegoId, ip, ganancia = 0) {
    const now = new Date();
    const reasons = [];
    let maxSeverity = 'low';
    let autoFlag = false;

    try {
        // ⭐ PASO 1: Registrar esta descarga
        await DownloadTracking.create({
            usuario,
            juegoId,
            ip,
            timestamp: now,
            ganancia
        });

        // ⭐ PASO 2: Obtener TODAS las estadísticas en UNA SOLA QUERY
        const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
        const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const stats = await DownloadTracking.aggregate([
            {
                $match: {
                    usuario,
                    timestamp: { $gte: oneDayAgo }
                }
            },
            {
                $facet: {
                    // Contar descargas por periodo
                    lastMinute: [
                        { $match: { timestamp: { $gte: oneMinuteAgo } } },
                        { $count: "count" }
                    ],
                    lastHour: [
                        { $match: { timestamp: { $gte: oneHourAgo } } },
                        { $count: "count" }
                    ],
                    lastDay: [
                        { $count: "count" }
                    ],
                    // IPs únicas en la última hora
                    uniqueIPsLastHour: [
                        { $match: { timestamp: { $gte: oneHourAgo } } },
                        { $group: { _id: "$ip" } },
                        { $group: { _id: null, ips: { $push: "$_id" }, count: { $sum: 1 } } }
                    ],
                    // Ganancias totales última hora
                    earningsLastHour: [
                        { $match: { timestamp: { $gte: oneHourAgo } } },
                        { $group: { _id: null, total: { $sum: "$ganancia" } } }
                    ],
                    // Últimas 5 descargas para análisis de tiempo
                    recentDownloads: [
                        { $match: { timestamp: { $gte: oneHourAgo } } },
                        { $sort: { timestamp: -1 } },
                        { $limit: 5 },
                        { $project: { timestamp: 1 } }
                    ]
                }
            }
        ]);

        const data = stats[0];
        
        // Extraer valores
        const downloadsLastMinute = data.lastMinute[0]?.count || 0;
        const downloadsLastHour = data.lastHour[0]?.count || 0;
        const downloadsLastDay = data.lastDay[0]?.count || 0;
        const uniqueIPsData = data.uniqueIPsLastHour[0] || { count: 0, ips: [] };
        const totalEarnings = data.earningsLastHour[0]?.total || 0;
        const recentDownloads = data.recentDownloads || [];

        // ⭐ PASO 3: DETECCIÓN DE ANOMALÍAS

        // 3.1 Velocidad de descarga anormal
        if (downloadsLastMinute > THRESHOLDS.MAX_DOWNLOADS_PER_MINUTE) {
            reasons.push({
                tipo: 'download_velocity',
                mensaje: `${downloadsLastMinute} descargas en 1 minuto (máx: ${THRESHOLDS.MAX_DOWNLOADS_PER_MINUTE})`,
                valor: downloadsLastMinute
            });
            maxSeverity = 'critical';
            autoFlag = true;
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

        // 3.2 IP Hopping (VPN/Proxy abuse)
        if (uniqueIPsData.count > THRESHOLDS.MAX_IPS_PER_USER_PER_HOUR) {
            reasons.push({
                tipo: 'ip_hopping',
                mensaje: `${uniqueIPsData.count} IPs diferentes en 1 hora (posible VPN hopping)`,
                valor: uniqueIPsData.count,
                ips: uniqueIPsData.ips
            });
            maxSeverity = upgradeSeverity(maxSeverity, 'high');
            autoFlag = true;
        }

        // 3.3 Abuso desde una sola IP
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

        // 3.4 Tiempo entre descargas sospechoso
        if (recentDownloads.length >= 2) {
            let hasAnomalousSpeed = false;
            for (let i = 0; i < recentDownloads.length - 1; i++) {
                const timeDiff = (recentDownloads[i].timestamp - recentDownloads[i + 1].timestamp) / 1000;
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

        // 3.5 Spike de ganancias
        if (totalEarnings > THRESHOLDS.MAX_EARNINGS_PER_HOUR) {
            reasons.push({
                tipo: 'earnings_spike',
                mensaje: `$${totalEarnings.toFixed(2)} ganados en 1 hora (máx: $${THRESHOLDS.MAX_EARNINGS_PER_HOUR})`,
                valor: totalEarnings
            });
            maxSeverity = upgradeSeverity(maxSeverity, 'critical');
            autoFlag = true;
        }

        // ⭐ PASO 4: Registrar actividad sospechosa si se detectó
        if (reasons.length > 0) {
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

            logger.warn(`Fraude detectado - Usuario: @${usuario}, Severidad: ${maxSeverity.toUpperCase()}, Razones: ${reasons.length}`);
            
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
        logger.error(`Error en análisis de comportamiento: ${error.message}`);
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
 * Marcar usuario automáticamente en lista negra
 */
async function autoFlagUser(Usuario, usuario, razon) {
    try {
        const user = await Usuario.findOne({ usuario });
        if (!user) {
            logger.error(`Usuario no encontrado para auto-flag: @${usuario}`);
            return false;
        }

        if (!user.listaNegraAdmin) {
            user.listaNegraAdmin = true;
            user.fechaListaNegra = new Date();
            user.notasAdmin = (user.notasAdmin || '') + 
                `\n[AUTO-DETECCIÓN ${new Date().toLocaleString('es-ES')}]: ${razon}`;
            
            await user.save();
            
            logger.warn(`Usuario auto-marcado en lista negra: @${usuario} - Razón: ${razon}`);
            return true;
        } else {
            logger.info(`Usuario ya está en lista negra: @${usuario}`);
            return false;
        }
    } catch (error) {
        logger.error(`Error al auto-marcar usuario: ${error.message}`);
        return false;
    }
}

/**
 * Obtener estadísticas de actividad sospechosa
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
        logger.error(`Error obteniendo stats de fraude: ${error.message}`);
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
