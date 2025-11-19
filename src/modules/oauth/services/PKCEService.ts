import { sha256Base64Url } from '../../../shared/utils/crypto';

/**
 * PKCE (Proof Key for Code Exchange) Service
 * Implements RFC 7636 for OAuth 2.0 public clients
 *
 * PKCE prevents authorization code interception attacks by requiring
 * the client to provide a code_verifier that matches the original code_challenge
 */

export type CodeChallengeMethod = 'S256' | 'plain';

export interface PKCEValidationResult {
  valid: boolean;
  error?: string;
}

export class PKCEService {
  /**
   * Validate that code_challenge_method is supported (S256 only for security)
   * @param method - The code challenge method
   * @returns True if method is supported
   */
  static isValidMethod(method: string): method is CodeChallengeMethod {
    // Only S256 is supported for security reasons (plain is deprecated)
    return method === 'S256';
  }

  /**
   * Verify that code_verifier matches the code_challenge
   * @param codeVerifier - The code verifier from token request
   * @param codeChallenge - The original code challenge from authorization request
   * @param method - The code challenge method (must be S256)
   * @returns Validation result
   */
  static verify(
    codeVerifier: string,
    codeChallenge: string,
    method: CodeChallengeMethod
  ): PKCEValidationResult {
    // Validate code_verifier format (43-128 characters, unreserved characters only)
    if (!codeVerifier || codeVerifier.length < 43 || codeVerifier.length > 128) {
      return {
        valid: false,
        error: 'Invalid code_verifier: must be 43-128 characters',
      };
    }

    // Validate code_verifier contains only unreserved characters
    const unreservedChars = /^[A-Za-z0-9._~-]+$/;
    if (!unreservedChars.test(codeVerifier)) {
      return {
        valid: false,
        error: 'Invalid code_verifier: must contain only unreserved characters [A-Za-z0-9._~-]',
      };
    }

    // Only S256 method is supported
    if (method !== 'S256') {
      return {
        valid: false,
        error: 'Unsupported code_challenge_method: only S256 is supported',
      };
    }

    // Compute the expected code_challenge from code_verifier
    const computedChallenge = sha256Base64Url(codeVerifier);

    // Compare with the original code_challenge
    if (computedChallenge !== codeChallenge) {
      return {
        valid: false,
        error: 'Invalid code_verifier: does not match code_challenge',
      };
    }

    return { valid: true };
  }

  /**
   * Generate a code_challenge from a code_verifier (for testing purposes)
   * @param codeVerifier - The code verifier
   * @param method - The code challenge method (default: S256)
   * @returns The code challenge
   */
  static generateChallenge(codeVerifier: string, method: CodeChallengeMethod = 'S256'): string {
    if (method === 'S256') {
      return sha256Base64Url(codeVerifier);
    }

    // Plain method is not recommended but included for completeness
    return codeVerifier;
  }

  /**
   * Validate code_challenge format
   * @param codeChallenge - The code challenge to validate
   * @returns True if format is valid
   */
  static isValidCodeChallenge(codeChallenge: string): boolean {
    // Code challenge should be 43+ characters (base64url encoded SHA256)
    if (!codeChallenge || codeChallenge.length < 43) {
      return false;
    }

    // Validate it's base64url format
    const base64UrlPattern = /^[A-Za-z0-9_-]+$/;
    return base64UrlPattern.test(codeChallenge);
  }

  /**
   * Validate PKCE parameters for authorization request
   * @param codeChallenge - The code challenge
   * @param codeChallengeMethod - The code challenge method
   * @returns Validation result
   */
  static validateAuthorizationRequest(
    codeChallenge: string | undefined,
    codeChallengeMethod: string | undefined
  ): PKCEValidationResult {
    // PKCE is mandatory - both parameters must be present
    if (!codeChallenge || !codeChallengeMethod) {
      return {
        valid: false,
        error: 'PKCE is mandatory: code_challenge and code_challenge_method are required',
      };
    }

    // Validate method
    if (!this.isValidMethod(codeChallengeMethod)) {
      return {
        valid: false,
        error: 'Invalid code_challenge_method: only S256 is supported',
      };
    }

    // Validate code_challenge format
    if (!this.isValidCodeChallenge(codeChallenge)) {
      return {
        valid: false,
        error: 'Invalid code_challenge format',
      };
    }

    return { valid: true };
  }
}
