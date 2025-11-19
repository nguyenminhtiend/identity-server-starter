import { db, users, organizations, clients } from './index.js';
import { hashPassword, generateRandomToken, sha256Hash as _sha256Hash } from '../utils/crypto.js';
import { KeyGenerationService } from '../../modules/key-management/services/KeyGenerationService.js';
import * as dotenv from 'dotenv';

dotenv.config();

const isMultiTenantEnabled = process.env.ENABLE_MULTI_TENANT === 'true';

async function seed() {
  console.info('🌱 Seeding database...\n');

  try {
    // 1. Generate initial signing key
    console.info('1️⃣  Generating initial signing key...');
    const keyService = new KeyGenerationService();
    await keyService.generateInitialKey();
    console.info('   ✓ Signing key created\n');

    // 2. Create test user
    console.info('2️⃣  Creating test user...');
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

    console.info(`   ✓ Test user created: ${testUser.email}`);
    console.info(`   Password: Test123456!\n`);

    // 3. Create test organization (if multi-tenant enabled)
    let testOrganization = null;
    if (isMultiTenantEnabled) {
      console.info('3️⃣  Creating test organization...');
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

      console.info(`   ✓ Organization created: ${testOrganization.name}\n`);
    } else {
      console.info('3️⃣  Multi-tenant disabled, skipping organization creation\n');
    }

    // 4. Create sample OAuth clients
    console.info('4️⃣  Creating sample OAuth clients...\n');

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
        organizationId: testOrganization?.id || null,
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

    console.info('   ✓ Confidential Client (Backend Web App):');
    console.info(`     Client ID: ${confidentialClient.clientId}`);
    console.info(`     Client Secret: ${confidentialClientSecret}`);
    console.info(`     Grant Types: authorization_code, refresh_token, client_credentials\n`);

    // 4b. Public client (SPA with PKCE)
    const publicSpaClientId = `client_${generateRandomToken(16)}`;

    const [publicSpaClient] = await db
      .insert(clients)
      .values({
        clientId: publicSpaClientId,
        clientSecretHash: null, // No secret for public clients
        name: 'Single Page Application',
        clientType: 'public',
        organizationId: testOrganization?.id || null,
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

    console.info('   ✓ Public Client (SPA):');
    console.info(`     Client ID: ${publicSpaClient.clientId}`);
    console.info(`     No client secret (public client, uses PKCE)`);
    console.info(`     Grant Types: authorization_code, refresh_token`);
    console.info(`     CORS Origins: http://localhost:5173, http://localhost:3000\n`);

    // 4c. Mobile app client (public with custom redirect URIs)
    const mobileClientId = `client_${generateRandomToken(16)}`;

    const [mobileClient] = await db
      .insert(clients)
      .values({
        clientId: mobileClientId,
        clientSecretHash: null, // No secret for public clients
        name: 'Mobile Application',
        clientType: 'public',
        organizationId: testOrganization?.id || null,
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

    console.info('   ✓ Public Client (Mobile App):');
    console.info(`     Client ID: ${mobileClient.clientId}`);
    console.info(`     No client secret (public client, uses PKCE)`);
    console.info(`     Grant Types: authorization_code, refresh_token`);
    console.info(`     Redirect URIs: myapp://callback, com.example.myapp://callback\n`);

    // Summary
    console.info('✅ Database seeded successfully!\n');
    console.info('📝 Summary:');
    console.info(`   • Test User: ${testUser.email} / Test123456!`);
    if (testOrganization) {
      console.info(`   • Organization: ${testOrganization.name} (${testOrganization.slug})`);
    }
    console.info(`   • Clients Created: 3 (1 confidential, 2 public)`);
    console.info(`   • Signing Key: Generated and stored\n`);

    console.info('🔐 Client Credentials (save these securely):');
    console.info('─'.repeat(60));
    console.info(`Confidential Client:`);
    console.info(`  Client ID:     ${confidentialClient.clientId}`);
    console.info(`  Client Secret: ${confidentialClientSecret}`);
    console.info(`\nPublic SPA Client:`);
    console.info(`  Client ID:     ${publicSpaClient.clientId}`);
    console.info(`\nMobile App Client:`);
    console.info(`  Client ID:     ${mobileClient.clientId}`);
    console.info('─'.repeat(60));
  } catch (error) {
    console.error('❌ Seeding failed:', error);
    throw error;
  } finally {
    process.exit(0);
  }
}

// Run seed
seed().catch((error) => {
  console.error('Fatal error during seeding:', error);
  process.exit(1);
});
