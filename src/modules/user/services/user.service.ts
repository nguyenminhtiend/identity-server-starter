import { eq } from 'drizzle-orm';
import { db } from '../../../shared/database';
import { users } from '../../../shared/database/schema';
import { hashPassword, verifyPassword } from '../../../shared/utils/crypto.util';
import type { IUserService } from './interfaces/user-service.interface';

/**
 * User Service
 * Handles user management and authentication
 */
export class UserService implements IUserService {
  /**
   * Create a new user account
   */
  async createUser(email: string, password: string): Promise<string> {
    // Check if email already exists
    const existingUser = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
    });

    if (existingUser !== undefined) {
      throw new Error('Email already exists');
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Create user
    const [newUser] = await db
      .insert(users)
      .values({
        email: email.toLowerCase(),
        passwordHash,
        emailVerified: false,
      })
      .returning({ id: users.id });

    if (newUser === undefined) {
      throw new Error('Failed to create user');
    }

    return newUser.id;
  }

  /**
   * Authenticate user with email and password
   */
  async authenticateUser(email: string, password: string): Promise<string | null> {
    // Find user by email
    const user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
      columns: {
        id: true,
        passwordHash: true,
      },
    });

    if (user === undefined) {
      return null;
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, user.passwordHash);

    if (!isValidPassword) {
      return null;
    }

    return user.id;
  }

  /**
   * Get user by ID
   */
  async getUserById(userId: string): Promise<{
    id: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  } | null> {
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      columns: {
        id: true,
        email: true,
        emailVerified: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return user ?? null;
  }

  /**
   * Get user by email
   */
  async getUserByEmail(email: string): Promise<{
    id: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  } | null> {
    const user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
      columns: {
        id: true,
        email: true,
        emailVerified: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return user ?? null;
  }

  /**
   * Verify user email
   */
  async verifyEmail(userId: string): Promise<void> {
    await db
      .update(users)
      .set({
        emailVerified: true,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId));
  }

  /**
   * Update user password
   */
  async updatePassword(userId: string, newPassword: string): Promise<void> {
    const passwordHash = await hashPassword(newPassword);

    await db
      .update(users)
      .set({
        passwordHash,
        updatedAt: new Date(),
      })
      .where(eq(users.id, userId));
  }

  /**
   * Check if email exists
   */
  async emailExists(email: string): Promise<boolean> {
    const user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
      columns: {
        id: true,
      },
    });

    return user !== undefined;
  }
}
