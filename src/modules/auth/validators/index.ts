import { z } from 'zod';

/**
 * Authentication Validation Schemas
 * Email, password, and user registration validation
 */

// Email validation
export const emailSchema = z
  .string()
  .min(1, 'Email is required')
  .email('Invalid email format')
  .max(255, 'Email too long')
  .toLowerCase()
  .trim();

// Password validation (2025 standards)
export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password too long')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(
    /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/,
    'Password must contain at least one special character'
  );

// Username (optional, if you want to support usernames)
export const usernameSchema = z
  .string()
  .min(3, 'Username must be at least 3 characters')
  .max(50, 'Username too long')
  .regex(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscore, and dash')
  .trim();

/**
 * Login Request
 * POST /login
 */
export const loginRequestSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
  remember: z.boolean().optional().default(false),
});

export type LoginRequest = z.infer<typeof loginRequestSchema>;

/**
 * Registration Request
 * POST /register
 */
export const registerRequestSchema = z
  .object({
    email: emailSchema,
    password: passwordSchema,
    confirmPassword: z.string().min(1, 'Please confirm your password'),
    acceptTerms: z
      .boolean()
      .refine((val) => val === true, { message: 'You must accept the terms of service' }),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

export type RegisterRequest = z.infer<typeof registerRequestSchema>;

/**
 * Password Reset Request
 * POST /forgot-password
 */
export const forgotPasswordRequestSchema = z.object({
  email: emailSchema,
});

export type ForgotPasswordRequest = z.infer<typeof forgotPasswordRequestSchema>;

/**
 * Password Reset Confirmation
 * POST /reset-password
 */
export const resetPasswordRequestSchema = z
  .object({
    token: z.string().min(1, 'Reset token is required'),
    password: passwordSchema,
    confirmPassword: z.string().min(1, 'Please confirm your password'),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

export type ResetPasswordRequest = z.infer<typeof resetPasswordRequestSchema>;

/**
 * Email Verification Request
 * POST /verify-email
 */
export const verifyEmailRequestSchema = z.object({
  token: z.string().min(1, 'Verification token is required'),
});

export type VerifyEmailRequest = z.infer<typeof verifyEmailRequestSchema>;

/**
 * Change Password Request (authenticated user)
 * POST /change-password
 */
export const changePasswordRequestSchema = z
  .object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: passwordSchema,
    confirmPassword: z.string().min(1, 'Please confirm your new password'),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  })
  .refine((data) => data.currentPassword !== data.newPassword, {
    message: 'New password must be different from current password',
    path: ['newPassword'],
  });

export type ChangePasswordRequest = z.infer<typeof changePasswordRequestSchema>;

/**
 * Update Profile Request
 * PUT /profile
 */
export const updateProfileRequestSchema = z.object({
  email: emailSchema.optional(),
  username: usernameSchema.optional(),
  // Add other profile fields as needed
});

export type UpdateProfileRequest = z.infer<typeof updateProfileRequestSchema>;
