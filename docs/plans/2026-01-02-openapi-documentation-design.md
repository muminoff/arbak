# OpenAPI Documentation Enhancement Design

> **Goal:** Enhance Swagger/OpenAPI documentation with industry-standard conventions for internal team use.

## Conventions

### 1. API Info & Tags
- Title: "Arbak API"
- Description: Full paragraph explaining RLS, JWT auth, key concepts
- Tags with sentence descriptions including auth/RLS context

### 2. Endpoint Documentation
- **operation_id**: camelCase verb+noun (e.g., `registerUser`, `listDocuments`)
- **summary**: Short imperative phrase, 5-7 words max
- **description**: 2-3 sentences covering behavior and auth requirements
- **request_body**: Include description of what payload represents

### 3. Response Documentation
- 200: Successful GET, PUT, DELETE
- 201: Successful POST creating resource
- 400: Validation errors
- 401: Missing/invalid auth
- 403: Authenticated but unauthorized
- 404: Resource not found
- 409: Conflict (duplicate email, etc.)
- Descriptions state outcome, not status code

### 4. Schema Documentation
- Struct-level: Business context description
- Field-level: Constraints, defaults, format hints
- Examples: Realistic values

### 5. Error Consistency
- Single ErrorResponse format across all endpoints
- Specific error messages per status code

## Files to Update
1. `src/openapi.rs` - API info, tags
2. `src/handlers/auth_handlers.rs` - Auth endpoint annotations
3. `src/handlers/document_handlers.rs` - Document endpoint annotations
4. `src/models/user.rs` - User schema descriptions
5. `src/models/document.rs` - Document schema descriptions
6. `src/services/auth_service.rs` - Auth schemas
7. `src/error.rs` - ErrorResponse schema
