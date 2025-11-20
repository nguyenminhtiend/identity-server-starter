---
trigger: always_on
---

# Project Coding Conventions

## File & Folder Naming

- **File Naming Pattern**: `[feature-name].[role].ts`
  - `[feature-name]` must be in **kebab-case**
  - `[role]` must clearly define the architectural layer
  - Valid roles: `controller`, `service`, `route`, `model`, `interface`, `middleware`, `util`, `type`, `config`, `dto`, `validator`
  - Examples:
    - Correct: `user-profile.controller.ts`, `oauth.service.ts`, `create-order.dto.ts`
    - Incorrect: `UserProfileController.ts`, `auth-service.ts`, `user.ts`
- **Folder Naming**: Use **kebab-case** for all directory names
  - Examples: `user-management/`, `core-services/`, `api-routes/`

## TypeScript Style

- Use **inline type imports**: `import { type Foo } from './foo'` (NOT `import type { Foo }`)
- Prefer **interfaces over types** for object shapes
- Use **strict type checking** - avoid `any`, use proper types
- Handle promises properly - always await or handle with `.catch()`
- Use **consistent naming**:
  - PascalCase for classes, interfaces, types
  - camelCase for variables, functions, parameters
  - UPPER_SNAKE_CASE for constants

## Code Quality

- Add **JSDoc comments** for all exported functions, classes, and complex logic
- Use the **logger** (pino) instead of console.log/error
  - Import: `import { logger } from '../shared/utils/logger.js'`
  - Usage: `logger.info()`, `logger.error()`, `logger.warn()`
- Use **dependency injection** pattern where applicable
- Prefer **nullish coalescing** (`??`) and **optional chaining** (`?.`)
- Use **async/await** over raw promises
- Always use **curly braces** for conditionals

## Formatting (Prettier)

- Single quotes for strings
- Semicolons required
- 100 character line width
- 2 space indentation
- Arrow function parentheses always
- Trailing commas in ES5 style

## Import/Export

- Use ES modules (NO `.js` or `.ts` extensions in imports unless required by specific config)
- **Always import from index files using folder names**: `import { Foo } from './folder'` (NOT `import { Foo } from './folder/index.js'`)
- **Never import directly from files**: Use barrel exports (index files) instead
  - Correct: `import { UserService } from './services'`
  - Incorrect: `import { UserService } from './services/user.service.js'`
- Group imports: external packages first, then internal modules
- No duplicate imports
- Use type imports for types only: `import { type Foo } from './types'`

## Error Handling

- Use `OAuthError` class for OAuth/OIDC errors
- **Relay on Express 5 native promise handling** (No `asyncHandler` wrapper needed)
- Validate inputs with Zod schemas
- Provide descriptive error messages

## Security

- Never log sensitive data (passwords, tokens, secrets)
- Validate and sanitize all user inputs
- Use prepared statements for database queries
- Follow OAuth 2.0 and OIDC security best practices

## Workflow & Verification

- **After writing or modifying code**, you MUST run the quality check command: `pnpm quality`
- **If the check fails**:
  1. Read the error output carefully.
  2. Fix the specific linting, formatting, or type issues.
  3. Run `pnpm quality` again to verify.
- **Do not declare a task complete** until `pnpm quality` runs without error.
