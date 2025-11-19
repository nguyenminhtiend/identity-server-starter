import { db, users, organizations, clients } from './index.js';
import { hashPassword, generateRandomToken, sha256Hash as _sha256Hash } from '../utils/crypto.js';
import { KeyGenerationService } from '../../modules/key-management/services/KeyGenerationService.js';
import * as dotenv from 'dotenv';

dotenv.config();

const isMultiTenantEnabled = process.env.ENABLE_MULTI_TENANT === 'true';

async function seed() {
  console.log('🌱 Seeding database...\n');

  try {
    // 1. Generate initial signing key
    console.log('1️⃣  Generating initial signing key...');
    const keyService = new KeyGenerationService();
    await keyService.generateInitialKey();
    console.log('   ✓ Signing key created\n');

    // 2. Create test user
    console.log('2️⃣  Creating test user...');
    const testPassword = await hashPassword('Test123456!');
    const [testUser] = await db
      .insert(users)
      .values({
        email: 'test@example.com',
        passwordHash: testPassword,
        emailVerified: true,
      })
      .returning();
    console.log(`   ✓ Test user created: ${testUser.email}`);
    console.log(`   Password: Test123456!\n`);

    // 3. Create test organization (if multi-tenant enabled)
    let testOrganization = null;
    if (isMultiTenantEnabled) {
      console.log('3️⃣  Creating test organization...');
      [testOrganization] = await db
        .insert(organizations)
        .values({
          name: 'Test Organization',
          slug: 'test-org',
          ownerUserId: testUser.id,
          isActive: true,
        })
        .returning();
      console.log(`   ✓ Organization created: ${testOrganization.name}\n`);
    } else {
      console.log('3️⃣  Multi-tenant disabled, skipping organization creation\n');
    }

    // 4. Create sample OAuth clients
    console.log('4️⃣  Creating sample OAuth clients...\n');

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

    console.log('   ✓ Confidential Client (Backend Web App):');
    console.log(`     Client ID: ${confidentialClient.clientId}`);
    console.log(`     Client Secret: ${confidentialClientSecret}`);
    console.log(`     Grant Types: authorization_code, refresh_token, client_credentials\n`);

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

    console.log('   ✓ Public Client (SPA):');
    console.log(`     Client ID: ${publicSpaClient.clientId}`);
    console.log(`     No client secret (public client, uses PKCE)`);
    console.log(`     Grant Types: authorization_code, refresh_token`);
    console.log(`     CORS Origins: http://localhost:5173, http://localhost:3000\n`);

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

    console.log('   ✓ Public Client (Mobile App):');
    console.log(`     Client ID: ${mobileClient.clientId}`);
    console.log(`     No client secret (public client, uses PKCE)`);
    console.log(`     Grant Types: authorization_code, refresh_token`);
    console.log(`     Redirect URIs: myapp://callback, com.example.myapp://callback\n`);

    // Summary
    console.log('✅ Database seeded successfully!\n');
    console.log('📝 Summary:');
    console.log(`   • Test User: ${testUser.email} / Test123456!`);
    if (testOrganization) {
      console.log(`   • Organization: ${testOrganization.name} (${testOrganization.slug})`);
    }
    console.log(`   • Clients Created: 3 (1 confidential, 2 public)`);
    console.log(`   • Signing Key: Generated and stored\n`);

    console.log('🔐 Client Credentials (save these securely):');
    console.log('─'.repeat(60));
    console.log(`Confidential Client:`);
    console.log(`  Client ID:     ${confidentialClient.clientId}`);
    console.log(`  Client Secret: ${confidentialClientSecret}`);
    console.log(`\nPublic SPA Client:`);
    console.log(`  Client ID:     ${publicSpaClient.clientId}`);
    console.log(`\nMobile App Client:`);
    console.log(`  Client ID:     ${mobileClient.clientId}`);
    console.log('─'.repeat(60));
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
