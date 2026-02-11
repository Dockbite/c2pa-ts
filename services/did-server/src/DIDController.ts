/**
 * DID Document verification method
 */
export interface DIDVerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyJwk?: {
        kty: string;
        crv: string;
        x: string;
        y?: string;
        use?: string;
        key_ops?: string[];
    };
    publicKeyMultibase?: string;
}

/**
 * DID Document structure according to W3C DID specification
 */
export interface DIDDocument {
    '@context': string | string[];
    id: string;
    verificationMethod?: DIDVerificationMethod[];
    authentication?: (string | DIDVerificationMethod)[];
    assertionMethod?: (string | DIDVerificationMethod)[];
    keyAgreement?: (string | DIDVerificationMethod)[];
    capabilityInvocation?: (string | DIDVerificationMethod)[];
    capabilityDelegation?: (string | DIDVerificationMethod)[];
    service?: {
        id: string;
        type: string;
        serviceEndpoint: string | string[];
    }[];
    alsoKnownAs?: string[];
    /**
     * Optional file hash for content verification
     * Used to link the DID document to a specific file
     */
    fileHash?: string;
}

/**
 * Result of DID document resolution
 */
export interface DIDResolutionResult {
    didDocument: DIDDocument | null;
    didResolutionMetadata: {
        contentType?: string;
        error?: string;
        message?: string;
        retrieved?: string;
    };
    didDocumentMetadata: Record<string, unknown>;
}
/**
 * DID method resolver function type
 */
export type DIDMethodResolver = (did: string) => Promise<DIDResolutionResult>;

/**
 * Cache entry for resolved DID documents
 */
interface DIDCacheEntry {
    document: DIDDocument;
    resolvedAt: number;
    metadata: DIDResolutionResult['didResolutionMetadata'];
}

/**
 * DID Controller configuration options
 */
export interface DIDControllerOptions {
    /**
     * Cache TTL in milliseconds (default: 5 minutes)
     */
    cacheTTL?: number;

    /**
     * Maximum cache size (default: 100 entries)
     */
    maxCacheSize?: number;

    /**
     * Custom resolvers for specific DID methods
     */
    customResolvers?: Map<string, DIDMethodResolver>;

    /**
     * Whether to enable automatic caching (default: true)
     */
    enableCache?: boolean;

    /**
     * HTTP timeout for did:web resolution in milliseconds (default: 5000)
     */
    httpTimeout?: number;
}

/**
 * DID Controller
 *
 * Manages DID resolution, caching, and verification for multiple DID methods.
 * Provides a centralized service for working with Decentralized Identifiers (DIDs).
 *
 * Supported DID methods:
 * - did:web: Web-based DIDs resolved via HTTPS
 * - did:key: Self-contained cryptographic DIDs
 * - Custom methods via registered resolvers
 *
 * @example
 * ```typescript
 * const controller = new DIDController({
 *   cacheTTL: 300000, // 5 minutes
 *   maxCacheSize: 100
 * });
 *
 * // Resolve a DID
 * const result = await controller.resolve('did:web:example.com');
 * if (result.didDocument) {
 *   console.log('Resolved DID:', result.didDocument.id);
 * }
 *
 * // Register custom resolver
 * controller.registerResolver('ethr', async (did) => {
 *   // Custom Ethereum DID resolution logic
 *   return { ... };
 * });
 * ```
 */
export class DIDController {
    private cache: Map<string, DIDCacheEntry>;
    private resolvers: Map<string, DIDMethodResolver>;
    private readonly options: Required<DIDControllerOptions>;

    constructor(options: DIDControllerOptions = {}) {
        this.cache = new Map();
        this.resolvers = new Map();
        this.options = {
            cacheTTL: options.cacheTTL ?? 300000, // 5 minutes default
            maxCacheSize: options.maxCacheSize ?? 100,
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
            customResolvers: options.customResolvers ?? new Map(),
            enableCache: options.enableCache ?? true,
            httpTimeout: options.httpTimeout ?? 5000,
        };

        // Register any custom resolvers provided in options
        this.options.customResolvers.forEach((resolver, method) => {
            this.registerResolver(method, resolver);
        });
    }

    /**
     * Resolve a DID to its DID document
     * @param did - The DID to resolve
     * @param options - Resolution options
     * @returns Promise resolving to the DID resolution result
     */
    public async resolve(did: string, options?: { skipCache?: boolean }): Promise<DIDResolutionResult> {
        if (!this.validateDIDFormat(did)) {
            return {
                didDocument: null,
                didResolutionMetadata: {
                    error: 'invalidDid',
                    message: `Invalid DID format: ${did}`,
                },
                didDocumentMetadata: {},
            };
        }

        // Check cache unless skipCache is explicitly set
        if (this.options.enableCache && !options?.skipCache) {
            const cached = this.getFromCache(did);
            if (cached) {
                return {
                    didDocument: cached.document,
                    didResolutionMetadata: {
                        ...cached.metadata,
                        // fromCache: true,
                    },
                    didDocumentMetadata: {},
                };
            }
        }

        // Extract DID method
        const method = this.extractMethod(did);
        if (!method) {
            return {
                didDocument: null,
                didResolutionMetadata: {
                    error: 'invalidDid',
                    message: 'Could not extract DID method',
                },
                didDocumentMetadata: {},
            };
        }

        // Try custom resolver first
        if (this.resolvers.has(method)) {
            const resolver = this.resolvers.get(method)!;
            try {
                const result = await resolver(did);

                // Cache successful resolutions
                if (result.didDocument && this.options.enableCache) {
                    this.addToCache(did, result.didDocument, result.didResolutionMetadata);
                }

                return result;
            } catch (error) {
                return {
                    didDocument: null,
                    didResolutionMetadata: {
                        error: 'internalError',
                        message: error instanceof Error ? error.message : 'Resolver threw an error',
                    },
                    didDocumentMetadata: {},
                };
            }
        }

        // Built-in resolvers
        switch (method) {
            case 'web':
                return await this.resolveWebDID(did);
            case 'key':
                return this.resolveKeyDID(did);
            default:
                return {
                    didDocument: null,
                    didResolutionMetadata: {
                        error: 'methodNotSupported',
                        message: `No resolver available for DID method: ${method}`,
                    },
                    didDocumentMetadata: {},
                };
        }
    }

    /**
     * Register a custom resolver for a specific DID method
     * @param method - The DID method (e.g., 'ethr', 'ion')
     * @param resolver - The resolver function
     */
    public registerResolver(method: string, resolver: DIDMethodResolver): void {
        this.resolvers.set(method, resolver);
    }

    /**
     * Unregister a resolver for a specific DID method
     * @param method - The DID method to unregister
     * @returns True if a resolver was removed, false otherwise
     */
    public unregisterResolver(method: string): boolean {
        return this.resolvers.delete(method);
    }

    /**
     * Clear the DID document cache
     * @param did - Optional specific DID to clear, or undefined to clear all
     */
    public clearCache(did?: string): void {
        if (did) {
            this.cache.delete(did);
        } else {
            this.cache.clear();
        }
    }

    /**
     * Get verification methods that can be used for assertions
     * @param did - The DID or DID document
     * @returns Array of verification method IDs
     */
    public async getAssertionMethods(did: string | DIDDocument): Promise<string[]> {
        let doc: DIDDocument | null;

        if (typeof did === 'string') {
            const result = await this.resolve(did);
            doc = result.didDocument;
        } else {
            doc = did;
        }

        if (!doc?.assertionMethod) {
            return [];
        }

        return doc.assertionMethod.map(method => {
            if (typeof method === 'string') {
                return method;
            }
            return method.id;
        });
    }

    /**
     * Get a specific verification method by its ID
     * @param didOrDoc - The DID string or DID document
     * @param methodId - The ID of the verification method
     * @returns The verification method or undefined if not found
     */
    public async getVerificationMethod(
        didOrDoc: string | DIDDocument,
        methodId: string,
    ): Promise<DIDVerificationMethod | undefined> {
        let doc: DIDDocument | null;

        if (typeof didOrDoc === 'string') {
            const result = await this.resolve(didOrDoc);
            doc = result.didDocument;
        } else {
            doc = didOrDoc;
        }

        if (!doc?.verificationMethod) {
            return undefined;
        }

        return doc.verificationMethod.find(method => method.id === methodId);
    }

    /**
     * Validate DID format according to W3C DID specification
     * @param did - The DID to validate
     * @returns True if valid, false otherwise
     */
    public validateDIDFormat(did: string): boolean {
        // Basic DID format: did:method:method-specific-id
        const didRegex = /^did:[a-z0-9]+:[a-zA-Z0-9._%-]*[a-zA-Z0-9._-]+$/;
        return didRegex.test(did);
    }

    /**
     * Extract the DID method from a DID string
     * @param did - The DID string
     * @returns The method name or null
     */
    private extractMethod(did: string): string | null {
        const parts = did.split(':');
        return parts.length >= 3 && parts[0] === 'did' ? parts[1] : null;
    }

    /**
     * Resolve a did:web DID
     * @param did - The did:web identifier
     * @returns Promise resolving to the DID resolution result
     */
    private async resolveWebDID(did: string): Promise<DIDResolutionResult> {
        try {
            // Extract domain from did:web:domain format
            const parts = did.replace('did:web:', '').split(':');
            const domain = decodeURIComponent(parts[0]);
            const path = parts.slice(1).join('/');

            // Construct URL
            const protocol = domain.includes('localhost') ? 'http' : 'https';
            const url =
                path ? `${protocol}://${domain}/${path}/did.json` : `${protocol}://${domain}/.well-known/did.json`;

            // Fetch with timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.options.httpTimeout);

            try {
                const response = await fetch(url, {
                    signal: controller.signal,
                    headers: {
                        Accept: 'application/json',
                    },
                });
                clearTimeout(timeoutId);

                if (!response.ok) {
                    return {
                        didDocument: null,
                        didResolutionMetadata: {
                            error: 'notFound',
                            message: `Failed to fetch DID document: ${response.status} ${response.statusText}`,
                        },
                        didDocumentMetadata: {},
                    };
                }

                const didDocument = (await response.json()) as DIDDocument;

                // Validate document structure
                const validationError = this.validateDIDDocument(didDocument);
                if (validationError) {
                    return {
                        didDocument: null,
                        didResolutionMetadata: {
                            error: 'invalidDidDocument',
                            message: validationError,
                        },
                        didDocumentMetadata: {},
                    };
                }

                // Verify document ID matches requested DID
                if (didDocument.id !== did) {
                    return {
                        didDocument: null,
                        didResolutionMetadata: {
                            error: 'invalidDidDocument',
                            message: `DID document id (${didDocument.id}) does not match requested DID (${did})`,
                        },
                        didDocumentMetadata: {},
                    };
                }

                // Cache the result
                if (this.options.enableCache) {
                    this.addToCache(did, didDocument, {
                        contentType: response.headers.get('content-type') ?? 'application/json',
                    });
                }

                return {
                    didDocument,
                    didResolutionMetadata: {
                        contentType: response.headers.get('content-type') ?? 'application/json',
                    },
                    didDocumentMetadata: {},
                };
            } finally {
                clearTimeout(timeoutId);
            }
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                return {
                    didDocument: null,
                    didResolutionMetadata: {
                        error: 'internalError',
                        message: 'DID resolution timeout',
                    },
                    didDocumentMetadata: {},
                };
            }

            return {
                didDocument: null,
                didResolutionMetadata: {
                    error: 'internalError',
                    message: error instanceof Error ? error.message : 'Unknown error during DID resolution',
                },
                didDocumentMetadata: {},
            };
        }
    }

    /**
     * Resolve a did:key DID (basic implementation)
     * @param did - The did:key identifier
     * @returns The DID resolution result
     */
    private resolveKeyDID(did: string): DIDResolutionResult {
        // did:key is self-contained - the key material is in the identifier itself
        // This is a basic implementation that creates a minimal DID document
        try {
            const didDocument: DIDDocument = {
                '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
                id: did,
                verificationMethod: [
                    {
                        id: `${did}#key-1`,
                        type: 'JsonWebKey2020',
                        controller: did,
                        publicKeyMultibase: did.replace('did:key:', ''),
                    },
                ],
                authentication: [`${did}#key-1`],
                assertionMethod: [`${did}#key-1`],
            };

            // Cache the result
            if (this.options.enableCache) {
                this.addToCache(did, didDocument, {});
            }

            return {
                didDocument,
                didResolutionMetadata: {},
                didDocumentMetadata: {},
            };
        } catch {
            return {
                didDocument: null,
                didResolutionMetadata: {
                    error: 'invalidDid',
                    message: 'Invalid did:key format',
                },
                didDocumentMetadata: {},
            };
        }
    }

    /**
     * Validate a DID document structure
     * @param doc - The DID document to validate
     * @returns Error message or null if valid
     */
    private validateDIDDocument(doc: DIDDocument): string | null {
        if (!doc['@context']) {
            return 'DID document is missing required @context';
        }

        if (!doc.id || typeof doc.id !== 'string') {
            return 'DID document is missing required id';
        }

        if (!this.validateDIDFormat(doc.id)) {
            return `DID document has invalid id format: ${doc.id}`;
        }

        // Validate verification methods if present
        if (doc.verificationMethod) {
            for (const method of doc.verificationMethod) {
                const error = this.validateVerificationMethod(method);
                if (error) {
                    return error;
                }
            }
        }

        return null;
    }

    /**
     * Validate a verification method
     * @param method - The verification method to validate
     * @returns Error message or null if valid
     */
    private validateVerificationMethod(method: DIDVerificationMethod): string | null {
        if (!method.id || typeof method.id !== 'string') {
            return 'Verification method is missing id';
        }

        if (!method.type || typeof method.type !== 'string') {
            return 'Verification method is missing type';
        }

        if (!method.controller || typeof method.controller !== 'string') {
            return 'Verification method is missing controller';
        }

        // Must have either publicKeyJwk or publicKeyMultibase
        if (!method.publicKeyJwk && !method.publicKeyMultibase) {
            return 'Verification method must have either publicKeyJwk or publicKeyMultibase';
        }

        return null;
    }

    /**
     * Get a DID document from cache if available and not expired
     * @param did - The DID to look up
     * @returns The cached entry or undefined
     */
    private getFromCache(did: string): DIDCacheEntry | undefined {
        const entry = this.cache.get(did);
        if (!entry) {
            return undefined;
        }

        // Check if entry has expired
        const now = Date.now();
        if (now - entry.resolvedAt > this.options.cacheTTL) {
            this.cache.delete(did);
            return undefined;
        }

        return entry;
    }

    /**
     * Add a DID document to the cache
     * @param did - The DID
     * @param document - The DID document
     * @param metadata - Resolution metadata
     */
    private addToCache(
        did: string,
        document: DIDDocument,
        metadata: DIDResolutionResult['didResolutionMetadata'],
    ): void {
        // Enforce max cache size
        if (this.cache.size >= this.options.maxCacheSize) {
            // Remove oldest entry (first entry in Map)
            const firstKey = this.cache.keys().next().value;
            if (firstKey) {
                this.cache.delete(firstKey);
            }
        }

        this.cache.set(did, {
            document,
            resolvedAt: Date.now(),
            metadata,
        });
    }

    /**
     * Get cache statistics
     * @returns Cache statistics
     */
    public getCacheStats(): {
        size: number;
        maxSize: number;
        ttl: number;
    } {
        return {
            size: this.cache.size,
            maxSize: this.options.maxCacheSize,
            ttl: this.options.cacheTTL,
        };
    }
}

/**
 * Default global DID controller instance
 */
export const defaultDIDController = new DIDController();
