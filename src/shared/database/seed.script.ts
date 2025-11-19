import { db, users, organizations, clients } from './index.js';
import {
  hashPassword,
  generateRandomToken,
  sha256Hash as _sha256Hash,
} from '../utils/crypto.util.js';
import { KeyGenerationService } from '../../modules/key-management/services/key-generation.service.js';
import { logger } from '../utils/logger.util.js';
import * as dotenv from 'dotenv';

dotenv.config();

const isMultiTenantEnabled = process.env.ENABLE_MULTI_TENANT === 'true';

async function seed() {
  logger.info('🌱 Seeding database...\n');

  try {
    // 1. Generate initial signing key
    logger.info('1️⃣  Generating initial signing key...');
    const keyService = new KeyGenerationService();
    await keyService.generateInitialKey();
    logger.info('   ✓ Signing key created\n');

    // 2. Create test user
    logger.info('2️⃣  Creating test user...');
    const testPassword = await hashPassword('Test123456!');
    const [testUser] = await db
      .insert(users)
      .values({
        email: 'test@example.com',
        passwordHash: testPassword,
        emailVerified: true,
      })
      .returning();

    if (!testUser) {
      throw new Error('Failed to create test user');
    }

    logger.info(`   ✓ Test user created: ${testUser.email}`);
    logger.info(`   Password: Test123456!\n`);

    // 3. Create test organization (if multi-tenant enabled)
    let testOrganization = null;
    if (isMultiTenantEnabled) {
      logger.info('3️⃣  Creating test organization...');
      [testOrganization] = await db
        .insert(organizations)
        .values({
          name: 'Test Organization',
          slug: 'test-org',
          ownerUserId: testUser.id,
          isActive: true,
        })
        .returning();

      if (!testOrganization) {
        throw new Error('Failed to create test organization');
      }

      logger.info(`   ✓ Organization created: ${testOrganization.name}\n`);
    } else {
      logger.info('3️⃣  Multi-tenant disabled, skipping organization creation\n');
    }

    // 4. Create sample OAuth clients
    logger.info('4️⃣  Creating sample OAuth clients...\n');

    // 4a. Confidential client (backend web app)
    const confidentialClientId = `client_${generateRandomToken(16)}`;
    const confidentialClientSecret = generateRandomToken(32);
    const confidentialClientSecretHash = await hashPassword(confidentialClientSecret);

    const [confidentialClient] = await db
      .insert(clients)
      .values({
        clientId: confidentialClientId,
        clientSecretHash: confidentialClientSecretHash,
        name: 'Backend Web Application',
        clientType: 'confidential',
        organizationId: testOrganization?.id ?? null,
        redirectUris: ['http://localhost:3001/callback', 'http://localhost:3001/auth/callback'],
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
        allowedScopes: 'openid profile email',
        homepageUrl: 'http://localhost:3001',
        termsUrl: 'http://localhost:3001/terms',
        privacyUrl: 'http://localhost:3001/privacy',
        contacts: ['admin@example.com'],
        isActive: true,
      })
      .returning();

    if (!confidentialClient) {
      throw new Error('Failed to create confidential client');
    }

    logger.info('   ✓ Confidential Client (Backend Web App):');
    logger.info(`     Client ID: ${confidentialClient.clientId}`);
    logger.info(`     Client Secret: ${confidentialClientSecret}`);
    logger.info(`     Grant Types: authorization_code, refresh_token, client_credentials\n`);

    // 4b. Public client (SPA with PKCE)
    const publicSpaClientId = `client_${generateRandomToken(16)}`;

    const [publicSpaClient] = await db
      .insert(clients)
      .values({
        clientId: publicSpaClientId,
        clientSecretHash: null, // No secret for public clients
        name: 'Single Page Application',
        clientType: 'public',
        organizationId: testOrganization?.id ?? null,
        redirectUris: ['http://localhost:5173/callback', 'http://localhost:5173/auth/callback'],
        grantTypes: ['authorization_code', 'refresh_token'],
        allowedScopes: 'openid profile email',
        allowedCorsOrigins: ['http://localhost:5173', 'http://localhost:3000'],
        homepageUrl: 'http://localhost:5173',
        logoUrl: 'http://localhost:5173/logo.png',
        isActive: true,
      })
      .returning();

    if (!publicSpaClient) {
      throw new Error('Failed to create public SPA client');
    }

    logger.info('   ✓ Public Client (SPA):');
    logger.info(`     Client ID: ${publicSpaClient.clientId}`);
    logger.info(`     No client secret (public client, uses PKCE)`);
    logger.info(`     Grant Types: authorization_code, refresh_token`);
    logger.info(`     CORS Origins: http://localhost:5173, http://localhost:3000\n`);

    // 4c. Mobile app client (public with custom redirect URIs)
    const mobileClientId = `client_${generateRandomToken(16)}`;

    const [mobileClient] = await db
      .insert(clients)
      .values({
        clientId: mobileClientId,
        clientSecretHash: null, // No secret for public clients
        name: 'Mobile Application',
        clientType: 'public',
        organizationId: testOrganization?.id ?? null,
        redirectUris: ['myapp://callback', 'com.example.myapp://callback'],
        grantTypes: ['authorization_code', 'refresh_token'],
        allowedScopes: 'openid profile email offline_access',
        homepageUrl: 'https://example.com',
        termsUrl: 'https://example.com/terms',
        privacyUrl: 'https://example.com/privacy',
        isActive: true,
      })
      .returning();

    if (!mobileClient) {
      throw new Error('Failed to create mobile client');
    }

    logger.info('   ✓ Public Client (Mobile App):');
    logger.info(`     Client ID: ${mobileClient.clientId}`);
    logger.info(`     No client secret (public client, uses PKCE)`);
    logger.info(`     Grant Types: authorization_code, refresh_token`);
    logger.info(`     Redirect URIs: myapp://callback, com.example.myapp://callback\n`);

    // Summary
    logger.info('✅ Database seeded successfully!\n');
    logger.info('📝 Summary:');
    logger.info(`   • Test User: ${testUser.email} / Test123456!`);
    if (testOrganization) {
      logger.info(`   • Organization: ${testOrganization.name} (${testOrganization.slug})`);
    }
    logger.info(`   • Clients Created: 3 (1 confidential, 2 public)`);
    logger.info(`   • Signing Key: Generated and stored\n`);

    logger.info('🔐 Client Credentials (save these securely):');
    logger.info('─'.repeat(60));
    logger.info(`Confidential Client:`);
    logger.info(`  Client ID:     ${confidentialClient.clientId}`);
    logger.info(`  Client Secret: ${confidentialClientSecret}`);
    logger.info(`\nPublic SPA Client:`);
    logger.info(`  Client ID:     ${publicSpaClient.clientId}`);
    logger.info(`\nMobile App Client:`);
    logger.info(`  Client ID:     ${mobileClient.clientId}`);
    logger.info('─'.repeat(60));
  } catch (error) {
    logger.error({ err: error }, '❌ Seeding failed');
    throw error;
  } finally {
    process.exit(0);
  }
}

// Run seed
seed().catch((error) => {
  logger.error({ err: error }, 'Fatal error during seeding');
  process.exit(1);
});
