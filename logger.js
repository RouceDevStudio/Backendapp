// ========================================
// 📝 SISTEMA DE LOGGING PROFESIONAL
// ========================================

const winston = require('winston');
const config = require('./config');

// Formato personalizado
const customFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.printf(({ level, message, timestamp, stack }) => {
        const emoji = {
            error: '❌',
            warn: '⚠️',
            info: 'ℹ️',
            debug: '🔍',
            success: '✅'
        }[level] || 'ℹ️';
        
        const msg = `${timestamp} ${emoji} [${level.toUpperCase()}]: ${message}`;
        return stack ? `${msg}\n${stack}` : msg;
    })
);

// Crear logger
const logger = winston.createLogger({
    level: config.LOG_LEVEL,
    format: customFormat,
    transports: [
        // Console siempre
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                customFormat
            )
        })
    ],
});

// En producción, también guardar en archivos
if (config.NODE_ENV === 'production') {
    logger.add(new winston.transports.File({ 
        filename: 'logs/error.log', 
        level: 'error',
        maxsize: 5242880, // 5MB
        maxFiles: 5,
    }));
    
    logger.add(new winston.transports.File({ 
        filename: 'logs/combined.log',
        maxsize: 5242880, // 5MB
        maxFiles: 5,
    }));
}

// Helper para log de éxito (nivel custom)
logger.success = (message) => {
    logger.log('info', message, { level: 'success' });
};

module.exports = logger;
