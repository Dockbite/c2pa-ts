# CAWG Identity Assertion - Quick Start Guide

Get started with CAWG identity assertions in 5 minutes.

## Installation

```bash
npm install @trustnxt/c2pa-ts
# or
bun add @trustnxt/c2pa-ts
```

## Basic Usage

### 1. Import the Module

```typescript
import {
  // Creation
  createSignerPayload,
  createIdentityAssertion,
  
  // Validation
  validateIdentityAssertion,
  
  // Types
  SignatureType,
  NamedActorRole,
  
  // Status codes
  SuccessCode,
  hasStatusCode,
} from '@trustnxt/c2pa-ts/cawg';
```

### 2. Create an Identity Assertion

```typescript
// Step 1: Prepare your referenced assertions
const referencedAssertions = [
  {
    url: 'self#jumbf=c2pa/.../c2pa.hash.data',  // Hard binding (required)
    hash: new Uint8Array([/* hash bytes */]),
  },
  {
    url: 'self#jumbf=c2pa/.../c2pa.actions',
    hash: new Uint8Array([/* hash bytes */]),
  },
];

// Step 2: Create signer payload
const signerPayload = createSignerPayload({
  referencedAssertions,
  sigType: SignatureType.X509Cose,  // or 'cawg.x509.cose'
  roles: [NamedActorRole.Creator],   // Optional
});

// Step 3: Sign the payload (integrate with your signing service)
import { serializeSignerPayload } from '@trustnxt/c2pa-ts/cawg';

const payloadBytes = serializeSignerPayload(signerPayload);
const signature = await yourSigningService.sign(payloadBytes);

// Step 4: Create final identity assertion
const identityAssertion = createIdentityAssertion(
  signerPayload,
  signature
);

// Step 5: Serialize for embedding in C2PA manifest
import { serializeIdentityAssertion } from '@trustnxt/c2pa-ts/cawg';

const assertionData = serializeIdentityAssertion(identityAssertion);
// Now add to your C2PA manifest
```

### 3. Validate an Identity Assertion

```typescript
// Validate identity assertion from C2PA manifest
const result = await validateIdentityAssertion(
  assertionData,           // CBOR-encoded assertion
  'cawg.identity',        // Assertion label
  claimData,              // C2PA claim containing the assertion
  {
    // Optional: trust configuration
    checkRevocation: true,
    validationTime: new Date(),
  }
);

// Check if valid
if (result.valid) {
  console.log('✅ Identity assertion is valid!');
  
  // Check trust status
  if (hasStatusCode(result, SuccessCode.Trusted)) {
    console.log('✅ Identity is TRUSTED');
  } else {
    console.log('⚠️  Identity is well-formed but not in trust list');
  }
} else {
  console.error('❌ Validation failed:');
  result.statuses
    .filter(s => !s.success)
    .forEach(s => console.error(`  - ${s.code}: ${s.explanation}`));
}
```

## Common Patterns

### Pattern 1: Creator Attribution

```typescript
import { NamedActorRole, SignatureType } from '@trustnxt/c2pa-ts/cawg';

const creatorAssertion = createSignerPayload({
  referencedAssertions: [
    hardBindingAssertion,
    actionsAssertion,
    thumbnailAssertion,
  ],
  sigType: SignatureType.X509Cose,
  roles: [NamedActorRole.Creator],
});
```

### Pattern 2: Multiple Actors (Photographer + Editor)

```typescript
import { generateAssertionLabel } from '@trustnxt/c2pa-ts/cawg';

// Photographer's assertion
const photographerLabel = generateAssertionLabel('cawg.identity', 0);
const photographerPayload = createSignerPayload({
  referencedAssertions: [hardBinding, captureMetadata],
  sigType: SignatureType.X509Cose,
  roles: [NamedActorRole.Creator],
});

// Editor's assertion
const editorLabel = generateAssertionLabel('cawg.identity', 1);
const editorPayload = createSignerPayload({
  referencedAssertions: [hardBinding, editActions],
  sigType: SignatureType.X509Cose,
  roles: [NamedActorRole.Editor],
});
```

### Pattern 3: Publisher Endorsement

```typescript
// Publisher signs the creator's work
const publisherPayload = createSignerPayload({
  referencedAssertions: [
    hardBinding,
    creatorIdentityAssertion,  // Reference another identity assertion!
    publisherMetadata,
  ],
  sigType: SignatureType.X509Cose,
  roles: [NamedActorRole.Publisher],
});
```

### Pattern 4: Using Placeholder for Data Hash

```typescript
import { createPlaceholderAssertion } from '@trustnxt/c2pa-ts/cawg';

// When you need to know final file layout before signing
// (e.g., for JPEG with c2pa.hash.data)

// Step 1: Create placeholder
const placeholder = createPlaceholderAssertion(
  'cawg.identity',
  2048  // Estimate signature size
);

// Step 2: Add placeholder to manifest and compute data hash
// ... (your C2PA manifest creation)

// Step 3: Now create real identity assertion
const payload = createSignerPayload({ /* ... */ });
const signature = await sign(payload);
const assertion = createIdentityAssertion(
  payload,
  signature,
  placeholder.size  // Must match placeholder!
);
```

## Configuration

### Trust Configuration (X.509)

```typescript
import { createDefaultTrustConfiguration } from '@trustnxt/c2pa-ts/cawg';

const trustConfig = createDefaultTrustConfiguration();

// Add your own trust anchors
trustConfig.trustAnchors.push(
  yourCustomRootCertificate
);

// Use in validation
const result = await validateIdentityAssertion(
  assertionData,
  label,
  claimData,
  { trustConfiguration: trustConfig }
);
```

### Trusted ICA Issuers

```typescript
const result = await validateIdentityAssertion(
  assertionData,
  label,
  claimData,
  {
    trustedIcaIssuers: [
      'did:web:example-ica-provider.com',
      'did:web:trusted-identity-service.org',
    ],
  }
);
```

## Error Handling

```typescript
import { 
  FailureCode,
  getFailures,
} from '@trustnxt/c2pa-ts/cawg';

const result = await validateIdentityAssertion(/* ... */);

if (!result.valid) {
  const failures = getFailures(result);
  
  // Handle specific errors
  for (const failure of failures) {
    switch (failure.code) {
      case FailureCode.HardBindingMissing:
        console.error('Missing hard binding reference');
        break;
      case FailureCode.CredentialRevoked:
        console.error('Certificate was revoked!');
        break;
      case FailureCode.AssertionMismatch:
        console.error('Referenced assertion not found');
        break;
      default:
        console.error(`Validation error: ${failure.code}`);
    }
  }
}
```

## Type Safety

All types are fully typed in TypeScript:

```typescript
import type {
  IdentityAssertion,
  SignerPayloadMap,
  ValidationResult,
  HashedUriMap,
  IdentityAssertionCreationOptions,
} from '@trustnxt/c2pa-ts/cawg';

// Your IDE will provide full autocompletion and type checking
```

## Advanced: Identity Claims Aggregation

```typescript
import {
  createIcaCredential,
  signIcaCredential,
  VerifiedIdentityType,
} from '@trustnxt/c2pa-ts/cawg';

// Create ICA credential with verified identities
const credential = createIcaCredential(
  'did:web:identity-provider.com',
  {
    id: 'did:web:identity-provider.com:user:alice',
    verifiedIdentities: [
      {
        type: VerifiedIdentityType.SocialMedia,
        name: 'Alice Johnson',
        username: 'alice',
        uri: 'https://social.example/alice',
        provider: {
          name: 'Example Social',
          id: 'https://social.example',
        },
        verifiedAt: '2024-01-15T10:00:00Z',
      },
    ],
  },
  signerPayload,
  new Date(),
);

// Sign the credential
const signature = await signIcaCredential(
  credential,
  async (vcPayload) => {
    // Return COSE_Sign1 signature
    return await icaService.signCredential(vcPayload);
  }
);

// Use as identity assertion signature
const assertion = createIdentityAssertion(signerPayload, signature);
```

## Testing Your Implementation

```typescript
import { isWellFormedIdentityAssertion } from '@trustnxt/c2pa-ts/cawg';

// Quick validation of structure
if (isWellFormedIdentityAssertion(assertionData)) {
  console.log('✅ Structure looks good');
} else {
  console.error('❌ Malformed identity assertion');
}

// Full validation
const result = await validateIdentityAssertion(/* ... */);
console.log(`Found ${result.statuses.length} validation checks`);
```

## Common Gotchas

### ❌ Forgetting Hard Binding
```typescript
// This will throw an error:
const payload = createSignerPayload({
  referencedAssertions: [
    // Missing hard binding!
    { url: 'self#.../c2pa.actions', hash: /* ... */ },
  ],
  sigType: SignatureType.X509Cose,
});
// Error: Referenced assertions must include a hard binding
```

### ✅ Include Hard Binding
```typescript
const payload = createSignerPayload({
  referencedAssertions: [
    { url: 'self#.../c2pa.hash.data', hash: /* ... */ },  // ✅ Hard binding
    { url: 'self#.../c2pa.actions', hash: /* ... */ },
  ],
  sigType: SignatureType.X509Cose,
});
```

### ❌ Wrong Padding Size
```typescript
// When using placeholder, signature must fit
const assertion = createIdentityAssertion(
  payload,
  tooLargeSignature,
  1024  // Placeholder size too small!
);
// Error: Signature size exceeds placeholder size
```

### ✅ Estimate Correctly
```typescript
const placeholder = createPlaceholderAssertion(
  'cawg.identity',
  4096  // Generous estimate
);
```

## Next Steps

1. **Read the Full Documentation**: [README.md](./README.md)
2. **Understand Architecture**: [ARCHITECTURE.md](./ARCHITECTURE.md)
3. **See Implementation Details**: [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md)
4. **Integrate with C2PA**: Check your C2PA manifest creation code
5. **Set Up Signing**: Configure your signing service integration
6. **Configure Trust**: Set up trust anchors and trust lists
7. **Test**: Validate with real-world assets

## Getting Help

- 📖 Full documentation in [README.md](./README.md)
- 🏗️ Architecture details in [ARCHITECTURE.md](./ARCHITECTURE.md)
- 📋 Specification: [CAWG Identity Assertion v1.2](https://creator-assertions.github.io/identity/1.2/)
- 🔧 C2PA Spec: [C2PA Technical Specification](https://c2pa.org/specifications/)

## Quick Reference

### Key Functions
- `createSignerPayload()` - Build signer_payload
- `createIdentityAssertion()` - Create final assertion
- `validateIdentityAssertion()` - Validate assertion
- `serializeSignerPayload()` - CBOR encode for signing
- `serializeIdentityAssertion()` - CBOR encode for embedding

### Key Types
- `IdentityAssertion` - Complete assertion structure
- `SignerPayloadMap` - Data to be signed
- `ValidationResult` - Validation output
- `SignatureType` - Credential types
- `NamedActorRole` - Actor roles

### Key Constants
- `SignatureType.X509Cose` - X.509 with COSE
- `SignatureType.IdentityClaimsAggregation` - ICA credentials
- `NamedActorRole.Creator/Editor/Publisher/etc.` - Predefined roles
- `SuccessCode.Trusted/WellFormed` - Success statuses

---

**Ready to use? Start with the basic usage example above! 🚀**
