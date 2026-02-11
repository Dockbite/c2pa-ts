# Decentralised Identity Assertion

The `DecentralisedIdentityAssertion` enables C2PA manifests to include Decentralised Identifiers (DIDs) and their associated DID documents. This allows for verifiable, decentralised identity claims within C2PA content provenance.

## Overview

A Decentralised Identifier (DID) is a W3C standard for creating globally unique, verifiable identifiers that don't require a centralized registration authority. The assertion supports:

- **DID Storage**: Store any W3C-compliant DID
- **DID Document Resolution**: Resolve and validate DID documents
- **Multiple DID Methods**: Support for did:web, did:key, did:ethr, did:ion, and more
- **Verification Methods**: Access public keys for signature verification
- **Assertion Methods**: Identify which verification methods can be used for assertions

## Supported DID Methods

### did:web
Web-based DIDs that resolve via HTTPS:
```
did:web:example.com
did:web:localhost%3A3000
did:web:example.com:path:to:did
```

### did:key
Self-contained DIDs encoding public keys:
```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

### did:ethr
Ethereum-based DIDs:
```
did:ethr:0x1234567890abcdef1234567890abcdef12345678
```

### did:ion
ION (Identity Overlay Network) DIDs on Bitcoin:
```
did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw
```

## Basic Usage

### Creating an Assertion

```typescript
import { DecentralisedIdentityAssertion } from '@c2pa/ts/manifest/assertions';

// Create a new assertion
const didAssertion = new DecentralisedIdentityAssertion();

// Set the DID
didAssertion.did = 'did:web:example.com';

// Optionally, add a pre-resolved DID document
didAssertion.didDocument = {
    '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1'
    ],
    id: 'did:web:example.com',
    verificationMethod: [{
        id: 'did:web:example.com#key-1',
        type: 'JsonWebKey2020',
        controller: 'did:web:example.com',
        publicKeyJwk: {
            kty: 'EC',
            crv: 'P-256',
            x: 'KXx0bV4sOxysLGLwBvS6JzBKRqIgXa6QqJxLXVCTwRM',
            y: '8sLbqJVNnbK02UxZbN6J8g4xZbKMrLFeVcCKpPmYl5w'
        }
    }],
    authentication: ['did:web:example.com#key-1'],
    assertionMethod: ['did:web:example.com#key-1']
};
```

### Resolving a DID

```typescript
// Resolve a did:web DID (built-in support)
const result = await didAssertion.resolveDID('did:web:example.com');

if (result.didDocument) {
    console.log('DID resolved successfully');
    console.log('Verification methods:', result.didDocument.verificationMethod);
} else {
    console.error('Resolution failed:', result.didResolutionMetadata.error);
}

// Check if resolved
console.log('Is resolved:', didAssertion.isResolved);
```

### Custom DID Resolver

For DID methods beyond did:web, provide a custom resolver:

```typescript
import { DIDResolutionResult } from '@c2pa/ts/manifest/assertions';

// Custom resolver function
async function customResolver(did: string): Promise<DIDResolutionResult> {
    // Your custom resolution logic
    // e.g., integrate with did:ethr, did:ion, etc.
    
    try {
        const didDocument = await fetchFromYourResolver(did);
        
        return {
            didDocument,
            didResolutionMetadata: {
                contentType: 'application/json'
            },
            didDocumentMetadata: {}
        };
    } catch (error) {
        return {
            didDocument: null,
            didResolutionMetadata: {
                error: 'notFound',
                message: error.message
            },
            didDocumentMetadata: {}
        };
    }
}

// Use the custom resolver
const result = await didAssertion.resolveDID(
    'did:ethr:0x123...',
    customResolver
);
```

### Accessing Verification Methods

```typescript
// Get all assertion methods (verification methods that can be used for assertions)
const assertionMethods = didAssertion.getAssertionMethods();
console.log('Assertion methods:', assertionMethods);
// Output: ['did:web:example.com#key-1']

// Get a specific verification method
const verificationMethod = didAssertion.getVerificationMethod('did:web:example.com#key-1');
if (verificationMethod) {
    console.log('Public key:', verificationMethod.publicKeyJwk);
    console.log('Key type:', verificationMethod.type);
}
```

## Integration with C2PA Manifests

### Adding to a Manifest

```typescript
import { Manifest } from '@c2pa/ts';
import { DecentralisedIdentityAssertion } from '@c2pa/ts/manifest/assertions';

// Create manifest
const manifest = new Manifest();

// Create and configure DID assertion
const didAssertion = new DecentralisedIdentityAssertion();
didAssertion.did = 'did:web:creator.example.com';

// Resolve the DID (optional but recommended)
await didAssertion.resolveDID();

// Add assertion to manifest
manifest.claim.assertionStore.assertions.push(didAssertion);
```

### Reading from a Manifest

```typescript
import { AssertionLabels, DecentralisedIdentityAssertion } from '@c2pa/ts/manifest/assertions';

// Read manifest from asset
const manifest = await asset.getManifest();

// Find DID assertion
const didAssertion = manifest.claim.assertionStore.assertions.find(
    a => a.label === AssertionLabels.decentralisedIdentity
) as DecentralisedIdentityAssertion;

if (didAssertion) {
    console.log('Found DID:', didAssertion.did);
    
    if (didAssertion.isResolved) {
        console.log('DID Document:', didAssertion.didDocument);
        console.log('Verification methods:', didAssertion.getAssertionMethods());
    } else {
        // Resolve if not already resolved
        await didAssertion.resolveDID();
    }
}
```

## DID Document Structure

A DID document follows the W3C DID specification:

```typescript
interface DIDDocument {
    // Required: W3C DID context
    '@context': string | string[];
    
    // Required: The DID itself
    id: string;
    
    // Optional: Verification methods (public keys)
    verificationMethod?: Array<{
        id: string;
        type: string;
        controller: string;
        publicKeyJwk?: {
            kty: string;
            crv: string;
            x: string;
            y?: string;
        };
        publicKeyMultibase?: string;
    }>;
    
    // Optional: Methods for authentication
    authentication?: (string | VerificationMethod)[];
    
    // Optional: Methods for making assertions
    assertionMethod?: (string | VerificationMethod)[];
    
    // Optional: Methods for key agreement
    keyAgreement?: (string | VerificationMethod)[];
    
    // Optional: Services
    service?: Array<{
        id: string;
        type: string;
        serviceEndpoint: string | string[];
    }>;
}
```

## Use Cases

### 1. Creator Identity

Link content to a verified creator identity:

```typescript
const creatorAssertion = new DecentralisedIdentityAssertion();
creatorAssertion.did = 'did:web:artist.example.com';
await creatorAssertion.resolveDID();
```

### 2. Organizational Identity

Associate content with an organization:

```typescript
const orgAssertion = new DecentralisedIdentityAssertion();
orgAssertion.did = 'did:web:news.example.com';
await orgAssertion.resolveDID();
```

### 3. Multi-Signature Verification

Use verification methods for signature checks:

```typescript
const didAssertion = new DecentralisedIdentityAssertion();
didAssertion.did = 'did:web:signer.example.com';
await didAssertion.resolveDID();

// Get verification methods that can be used for assertions
const methods = didAssertion.getAssertionMethods();

// Verify signature using one of these methods
for (const methodId of methods) {
    const method = didAssertion.getVerificationMethod(methodId);
    if (method?.publicKeyJwk) {
        // Use the public key to verify signatures
        const verified = await verifySignature(
            signature,
            message,
            method.publicKeyJwk
        );
        if (verified) break;
    }
}
```

### 4. Decentralised Reputation

Combine with other assertions for reputation systems:

```typescript
// Creator's DID
const creatorDID = new DecentralisedIdentityAssertion();
creatorDID.did = 'did:web:creator.example.com';
await creatorDID.resolveDID();

// Verifier's DID
const verifierDID = new DecentralisedIdentityAssertion();
verifierDID.did = 'did:web:verifier.example.com';
await verifierDID.resolveDID();

// Add both to manifest
manifest.claim.assertionStore.assertions.push(creatorDID, verifierDID);
```

## did:web Resolution

The built-in did:web resolver follows the W3C DID specification:

- `did:web:example.com` → `https://example.com/.well-known/did.json`
- `did:web:example.com:path:to:did` → `https://example.com/path/to/did/did.json`
- `did:web:localhost%3A3000` → `http://localhost:3000/.well-known/did.json`

### Setting up a did:web DID

1. **Create your DID document** (`did.json`):

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:example.com",
  "verificationMethod": [{
    "id": "did:web:example.com#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:example.com",
    "publicKeyJwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  }],
  "authentication": ["did:web:example.com#key-1"],
  "assertionMethod": ["did:web:example.com#key-1"]
}
```

2. **Host at the well-known location**:
   - URL: `https://example.com/.well-known/did.json`
   - Content-Type: `application/json`
   - CORS headers: `Access-Control-Allow-Origin: *`

3. **Test resolution**:
   ```bash
   curl https://example.com/.well-known/did.json
   ```

## Validation

The assertion automatically validates:

- ✅ DID format compliance (W3C DID specification)
- ✅ DID document structure
- ✅ Required fields (@context, id)
- ✅ W3C DID v1 context presence
- ✅ Verification method structure
- ✅ Public key presence (publicKeyJwk or publicKeyMultibase)

## Error Handling

```typescript
try {
    const assertion = new DecentralisedIdentityAssertion();
    assertion.did = 'did:web:example.com';
    
    const result = await assertion.resolveDID();
    
    if (result.didResolutionMetadata.error) {
        switch (result.didResolutionMetadata.error) {
            case 'invalidDid':
                console.error('Invalid DID format');
                break;
            case 'notFound':
                console.error('DID document not found');
                break;
            case 'methodNotSupported':
                console.error('DID method not supported');
                break;
            case 'invalidDidDocument':
                console.error('Invalid DID document structure');
                break;
            default:
                console.error('Resolution error:', result.didResolutionMetadata.message);
        }
    }
} catch (error) {
    console.error('Validation error:', error.message);
}
```

## Best Practices

1. **Always validate DIDs** before adding to manifests
2. **Cache resolved DID documents** to avoid repeated network calls
3. **Include resolution metadata** for transparency
4. **Use HTTPS** for did:web DIDs in production
5. **Implement CORS** properly for did:web hosting
6. **Verify document ID** matches the requested DID
7. **Check assertion methods** before signature verification

## References

- [W3C DID Specification](https://www.w3.org/TR/did-core/)
- [DID Method Registry](https://w3c.github.io/did-spec-registries/)
- [did:web Specification](https://w3c-ccg.github.io/did-method-web/)
- [DID Resolution](https://w3c-ccg.github.io/did-resolution/)
- [C2PA Specification](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html)
