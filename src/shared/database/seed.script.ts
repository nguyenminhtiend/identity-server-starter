import { db, users, organizations, clients, signingKeys } from '.';
import { hashPassword, generateRandomToken, sha256Hash as _sha256Hash, logger } from '../utils';
import { KeyGenerationService } from '../../modules/key-management/services';
import { eq } from 'drizzle-orm';
import * as dotenv from 'dotenv';

dotenv.config();

const isMultiTenantEnabled = process.env.ENABLE_MULTI_TENANT === 'true';

async function seed() {
  logger.info('🌱 Seeding database...\n');

  try {
    // 1. Generate initial signing key (check if one already exists)
    logger.info('1️⃣  Checking signing keys...');
    const existingKeys = await db.select().from(signingKeys).where(eq(signingKeys.isActive, true));

    if (existingKeys.length === 0) {
      logger.info('   No signing keys found, generating initial key...');
      const keyService = new KeyGenerationService();
      await keyService.generateInitialKey();
      logger.info('   ✓ Signing key created\n');
    } else {
      logger.info(`   ✓ Signing keys already exist (${existingKeys.length} active keys)\n`);
    }

    // 2. Create test user (check if already exists)
    logger.info('2️⃣  Checking test user...');
    const existingUsers = await db.select().from(users).where(eq(users.email, 'test@example.com'));

    let testUser;
    if (existingUsers.length === 0) {
      logger.info('   Creating test user...');
      const testPassword = await hashPassword('Test123456!');
      const [newUser] = await db
        .insert(users)
        .values({
          email: 'test@example.com',
          passwordHash: testPassword,
          emailVerified: true,
        })
        .returning();

      if (!newUser) {
        throw new Error('Failed to create test user');
      }

      testUser = newUser;
      logger.info(`   ✓ Test user created: ${testUser.email}`);
      logger.info(`   Password: Test123456!\n`);
    } else {
      testUser = existingUsers[0];
      logger.info(`   ✓ Test user already exists: ${testUser!.email}\n`);
    }

    // 3. Create test organization (if multi-tenant enabled)
    let testOrganization = null;
    if (isMultiTenantEnabled) {
      logger.info('3️⃣  Checking test organization...');
      const existingOrgs = await db
        .select()
        .from(organizations)
        .where(eq(organizations.slug, 'test-org'));

      if (existingOrgs.length === 0) {
        logger.info('   Creating test organization...');
        const [newOrg] = await db
          .insert(organizations)
          .values({
            name: 'Test Organization',
            slug: 'test-org',
            ownerUserId: testUser!.id,
            isActive: true,
          })
          .returning();

        if (!newOrg) {
          throw new Error('Failed to create test organization');
        }

        testOrganization = newOrg;
        logger.info(`   ✓ Organization created: ${testOrganization.name}\n`);
      } else {
        testOrganization = existingOrgs[0];
        logger.info(`   ✓ Organization already exists: ${testOrganization!.name}\n`);
      }
    } else {
      logger.info('3️⃣  Multi-tenant disabled, skipping organization creation\n');
    }

    // 4. Create sample OAuth clients (check if they already exist by name)
    logger.info('4️⃣  Creating sample OAuth clients...\n');

    // 4a. Confidential client (backend web app)
    const existingConfidentialClients = await db
      .select()
      .from(clients)
      .where(eq(clients.name, 'Backend Web Application'));

    let confidentialClient;
    let confidentialClientSecret = '';

    if (existingConfidentialClients.length === 0) {
      const confidentialClientId = `client_${generateRandomToken(16)}`;
      confidentialClientSecret = generateRandomToken(32);
      const confidentialClientSecretHash = await hashPassword(confidentialClientSecret);

      const [newClient] = await db
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

      confidentialClient = newClient;
      logger.info('   ✓ Confidential Client (Backend Web App):');
      logger.info(`     Client ID: ${confidentialClient!.clientId}`);
      logger.info(`     Client Secret: ${confidentialClientSecret}`);
      logger.info(`     Grant Types: authorization_code, refresh_token, client_credentials\n`);
    } else {
      confidentialClient = existingConfidentialClients[0];
      logger.info('   ⚠ Confidential Client already exists (skipped)\n');
    }

    // 4b. Public client (SPA with PKCE)
    const existingSpaClients = await db
      .select()
      .from(clients)
      .where(eq(clients.name, 'Single Page Application'));

    let publicSpaClient;

    if (existingSpaClients.length === 0) {
      const publicSpaClientId = `client_${generateRandomToken(16)}`;

      const [newClient] = await db
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

      publicSpaClient = newClient;
      logger.info('   ✓ Public Client (SPA):');
      logger.info(`     Client ID: ${publicSpaClient!.clientId}`);
      logger.info(`     No client secret (public client, uses PKCE)`);
      logger.info(`     Grant Types: authorization_code, refresh_token`);
      logger.info(`     CORS Origins: http://localhost:5173, http://localhost:3000\n`);
    } else {
      publicSpaClient = existingSpaClients[0];
      logger.info('   ⚠ Public SPA Client already exists (skipped)\n');
    }

    // 4c. Mobile app client (public with custom redirect URIs)
    const existingMobileClients = await db
      .select()
      .from(clients)
      .where(eq(clients.name, 'Mobile Application'));

    let mobileClient;

    if (existingMobileClients.length === 0) {
      const mobileClientId = `client_${generateRandomToken(16)}`;

      const [newClient] = await db
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

      mobileClient = newClient;
      logger.info('   ✓ Public Client (Mobile App):');
      logger.info(`     Client ID: ${mobileClient!.clientId}`);
      logger.info(`     No client secret (public client, uses PKCE)`);
      logger.info(`     Grant Types: authorization_code, refresh_token`);
      logger.info(`     Redirect URIs: myapp://callback, com.example.myapp://callback\n`);
    } else {
      mobileClient = existingMobileClients[0];
      logger.info('   ⚠ Mobile App Client already exists (skipped)\n');
    }

    // Summary
    logger.info('✅ Database seeding completed!\n');
    logger.info('📝 Summary:');
    logger.info(`   • Test User: ${testUser!.email} / Test123456!`);
    if (testOrganization) {
      logger.info(`   • Organization: ${testOrganization.name} (${testOrganization.slug})`);
    }
    logger.info(`   • Clients: Checked and created as needed`);
    logger.info(`   • Signing Keys: Verified\n`);

    if (confidentialClient || publicSpaClient || mobileClient) {
      logger.info('🔐 New Client Credentials (save these securely):');
      logger.info('─'.repeat(60));
      if (confidentialClient) {
        logger.info(`Confidential Client:`);
        logger.info(`  Client ID:     ${confidentialClient.clientId}`);
        logger.info(`  Client Secret: ${confidentialClientSecret}`);
      }
      if (publicSpaClient) {
        logger.info(`\nPublic SPA Client:`);
        logger.info(`  Client ID:     ${publicSpaClient.clientId}`);
      }
      if (mobileClient) {
        logger.info(`\nMobile App Client:`);
        logger.info(`  Client ID:     ${mobileClient.clientId}`);
      }
      logger.info('─'.repeat(60));
    } else {
      logger.info('ℹ️  No new clients created (all already exist)');
    }
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
