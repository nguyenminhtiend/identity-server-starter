import pino from 'pino';
import { config } from '../config';

/**
 * Create a Pino logger instance with appropriate configuration
 * based on the environment (development/production)
 */
export const logger = pino({
  level: config.env === 'production' ? 'info' : 'debug',

  // Pretty print in development for better readability
  transport:
    config.env !== 'production'
      ? {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'HH:MM:ss',
            ignore: 'pid,hostname',
            singleLine: false,
          },
        }
      : undefined,

  // Base configuration
  base: {
    env: config.env,
  },

  // Timestamp configuration
  timestamp: pino.stdTimeFunctions.isoTime,

  // Format error objects properly
  formatters: {
    level: (label) => {
      return { level: label };
    },
  },
});

/**
 * Create a child logger with additional context
 * @param context Additional context to include in all logs
 */
export function createLogger(context: Record<string, unknown>) {
  return logger.child(context);
}
