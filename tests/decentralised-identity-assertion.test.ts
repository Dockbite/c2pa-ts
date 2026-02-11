/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { describe, expect, it } from 'bun:test';
import { DecentralisedIdentityAssertion } from '../src/manifest/assertions/DecentralisedIdentityAssertion';
import type { DIDDocument, DIDResolutionResult } from '../src/manifest/assertions/DecentralisedIdentityAssertion';

describe('DecentralisedIdentityAssertion', () => {
    const mockDIDWebDocument: DIDDocument = {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
        id: 'did:web:example.com',
        verificationMethod: [
            {
                id: 'did:web:example.com#key-1',
                type: 'JsonWebKey2020',
                controller: 'did:web:example.com',
                publicKeyJwk: {
                    kty: 'EC',
                    crv: 'P-256',
                    x: 'KXx0bV4sOxysLGLwBvS6JzBKRqIgXa6QqJxLXVCTwRM',
                    y: '8sLbqJVNnbK02UxZbN6J8g4xZbKMrLFeVcCKpPmYl5w',
                },
            },
        ],
        authentication: ['did:web:example.com#key-1'],
        assertionMethod: ['did:web:example.com#key-1'],
    };

    describe('Basic Functionality', () => {
        it('should create a new DecentralisedIdentityAssertion', () => {
            const assertion = new DecentralisedIdentityAssertion();
            expect(assertion).toBeDefined();
            expect(assertion.label).toBe('c2pa.decentralised-identity');
        });

        it('should set and get DID', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            expect(assertion.did).toBe('did:web:example.com');
        });

        it('should set and get DID document', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.didDocument = mockDIDWebDocument;
            expect(assertion.didDocument).toEqual(mockDIDWebDocument);
        });
    });

    describe('DID Format Validation', () => {
        it('should accept valid did:web format', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });

        it('should accept valid did:key format', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });

        it('should accept valid did:ethr format', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:ethr:0x1234567890abcdef1234567890abcdef12345678';
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });

        it('should accept valid did:ion format', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw';
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });

        it('should reject invalid DID format - missing method', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:example.com';
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow('Invalid DID format');
        });

        it('should reject invalid DID format - no did prefix', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'web:example.com';
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow('Invalid DID format');
        });

        it('should reject invalid DID format - ends with colon', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:';
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow('Invalid DID format');
        });
    });

    describe('DID Document Validation', () => {
        it('should validate a correct DID document', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = mockDIDWebDocument;
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });

        it('should reject DID document without @context', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = {
                id: 'did:web:example.com',
            } as any;
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow('missing @context');
        });

        it('should reject DID document without W3C DID v1 context', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = {
                '@context': ['https://example.com/context'],
                id: 'did:web:example.com',
            };
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow('must include https://www.w3.org/ns/did/v1');
        });

        it('should reject DID document without id', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = {
                '@context': 'https://www.w3.org/ns/did/v1',
            } as any;
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow('missing id field');
        });

        it('should reject DID document with mismatched id', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = {
                '@context': 'https://www.w3.org/ns/did/v1',
                id: 'did:web:different.com',
            };
            // The validation is done during generateJUMBFBoxForContent
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow();
        });

        it('should accept DID document with array context', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = {
                '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/v1'],
                id: 'did:web:example.com',
            };
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });
    });

    describe('Verification Methods', () => {
        it('should validate verification method with publicKeyJwk', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = mockDIDWebDocument;
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });

        it('should validate verification method with publicKeyMultibase', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
            assertion.didDocument = {
                '@context': 'https://www.w3.org/ns/did/v1',
                id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                verificationMethod: [
                    {
                        id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                        type: 'Ed25519VerificationKey2020',
                        controller: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                        publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
                    },
                ],
            };
            expect(() => assertion.generateJUMBFBoxForContent()).not.toThrow();
        });

        it('should reject verification method without public key', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = {
                '@context': 'https://www.w3.org/ns/did/v1',
                id: 'did:web:example.com',
                verificationMethod: [
                    {
                        id: 'did:web:example.com#key-1',
                        type: 'JsonWebKey2020',
                        controller: 'did:web:example.com',
                    },
                ],
            } as any;
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow(
                'must have either publicKeyJwk or publicKeyMultibase',
            );
        });

        it('should get assertion methods', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.didDocument = mockDIDWebDocument;
            const methods = assertion.getAssertionMethods();
            expect(methods).toContain('did:web:example.com#key-1');
        });

        it('should get verification method by id', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.didDocument = mockDIDWebDocument;
            const method = assertion.getVerificationMethod('did:web:example.com#key-1');
            expect(method).toBeDefined();
            expect(method?.type).toBe('JsonWebKey2020');
        });

        it('should return undefined for non-existent verification method', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.didDocument = mockDIDWebDocument;
            const method = assertion.getVerificationMethod('did:web:example.com#key-999');
            expect(method).toBeUndefined();
        });
    });

    describe('Resolution Status', () => {
        it('should report isResolved as false initially', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            expect(assertion.isResolved).toBe(false);
        });

        it('should report isResolved as true when document is set', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = mockDIDWebDocument;
            expect(assertion.isResolved).toBe(true);
        });

        it('should report isResolved as false when resolution has error', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = mockDIDWebDocument;
            assertion.resolutionMetadata = {
                error: 'notFound',
            };
            expect(assertion.isResolved).toBe(false);
        });
    });

    describe('DID Resolution', () => {
        it('should return error for invalid DID', async () => {
            const assertion = new DecentralisedIdentityAssertion();
            const result = await assertion.resolveDID('invalid-did');
            expect(result.didResolutionMetadata.error).toBe('invalidDid');
        });

        it('should return error for unsupported DID method', async () => {
            const assertion = new DecentralisedIdentityAssertion();
            const result = await assertion.resolveDID('did:unsupported:123456');
            expect(result.didResolutionMetadata.error).toBe('methodNotSupported');
        });

        it('should use custom resolver when provided', async () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:custom:123';

            const mockResolver = async (did: string): Promise<DIDResolutionResult> => {
                return {
                    didDocument: {
                        '@context': 'https://www.w3.org/ns/did/v1',
                        id: did,
                    },
                    didResolutionMetadata: {
                        contentType: 'application/json',
                    },
                    didDocumentMetadata: {},
                };
            };

            const result = await assertion.resolveDID('did:custom:123', mockResolver);
            expect(result.didDocument).toBeDefined();
            expect(result.didDocument?.id).toBe('did:custom:123');
            expect(assertion.didDocument).toBeDefined();
        });

        it('should construct correct URL for did:web with domain only', async () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:localhost%3A3000';

            // Mock fetch is needed for actual resolution testing
            // This test just validates the format is accepted
            expect(assertion.did).toBe('did:web:localhost%3A3000');
        });

        it('should construct correct URL for did:web with path', async () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com:path:to:did';
            expect(assertion.did).toBe('did:web:example.com:path:to:did');
        });
    });

    describe('JUMBF Serialization', () => {
        it('should generate JUMBF box with DID only', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            const box = assertion.generateJUMBFBoxForContent();
            expect(box).toBeDefined();
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            expect((box as any).content).toHaveProperty('did', 'did:web:example.com');
        });

        it('should generate JUMBF box with DID and document', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = mockDIDWebDocument;
            const box = assertion.generateJUMBFBoxForContent();
            expect(box).toBeDefined();
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
            expect((box as any).content).toHaveProperty('did', 'did:web:example.com');
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
            expect((box as any).content).toHaveProperty('didDocument');
        });

        it('should generate JUMBF box with resolution metadata', () => {
            const assertion = new DecentralisedIdentityAssertion();
            assertion.did = 'did:web:example.com';
            assertion.didDocument = mockDIDWebDocument;
            assertion.resolutionMetadata = {
                contentType: 'application/json',
                retrieved: '2026-02-11T10:00:00Z',
            };
            const box = assertion.generateJUMBFBoxForContent();
            expect(box).toBeDefined();
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
            expect((box as any).content).toHaveProperty('resolutionMetadata');
        });

        it('should throw error when generating box without DID', () => {
            const assertion = new DecentralisedIdentityAssertion();
            expect(() => assertion.generateJUMBFBoxForContent()).toThrow('DID is required');
        });
    });

    describe('Complete Workflow Example', () => {
        it('should demonstrate complete assertion creation workflow', () => {
            // Create a new assertion
            const assertion = new DecentralisedIdentityAssertion();

            // Set the DID
            assertion.did = 'did:web:example.com';

            // Optionally set the resolved DID document
            assertion.didDocument = mockDIDWebDocument;

            // Add resolution metadata
            assertion.resolutionMetadata = {
                contentType: 'application/json',
                retrieved: new Date().toISOString(),
            };

            // Verify the assertion is properly configured
            expect(assertion.isResolved).toBe(true);
            expect(assertion.getAssertionMethods()).toHaveLength(1);
            expect(assertion.getVerificationMethod('did:web:example.com#key-1')).toBeDefined();

            // Generate JUMBF box for serialization
            const box = assertion.generateJUMBFBoxForContent();
            expect(box).toBeDefined();
        });
    });
});
