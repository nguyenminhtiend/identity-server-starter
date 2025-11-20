/**
 * User Service Interface
 * Defines contract for user management operations
 */
export interface IUserService {
  /**
   * Create a new user account
   * @param email - User email address
   * @param password - Plain text password (will be hashed)
   * @returns Created user ID
   * @throws Error if email already exists
   */
  createUser(email: string, password: string): Promise<string>;

  /**
   * Authenticate user with email and password
   * @param email - User email address
   * @param password - Plain text password
   * @returns User ID if authentication successful, null otherwise
   */
  authenticateUser(email: string, password: string): Promise<string | null>;

  /**
   * Get user by ID
   * @param userId - User ID
   * @returns User object or null if not found
   */
  getUserById(userId: string): Promise<{
    id: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  } | null>;

  /**
   * Get user by email
   * @param email - User email address
   * @returns User object or null if not found
   */
  getUserByEmail(email: string): Promise<{
    id: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  } | null>;

  /**
   * Verify user email
   * @param userId - User ID
   */
  verifyEmail(userId: string): Promise<void>;

  /**
   * Update user password
   * @param userId - User ID
   * @param newPassword - New plain text password (will be hashed)
   */
  updatePassword(userId: string, newPassword: string): Promise<void>;

  /**
   * Check if email exists
   * @param email - User email address
   * @returns True if email exists, false otherwise
   */
  emailExists(email: string): Promise<boolean>;
}
