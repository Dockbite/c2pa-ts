import { IBox, JSONBox } from '../../jumbf';
import { BinaryHelper } from '../../util';
import { Claim } from '../Claim';
import * as raw from '../rawTypes';
import { ValidationStatusCode } from '../types';
import { ValidationError } from '../ValidationError';
import { Assertion } from './Assertion';
import { AssertionLabels } from './AssertionLabels';

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
 * Decentralised Identity Assertion
 *
 * This assertion contains a DID (Decentralised Identifier) and optionally
 * the resolved DID document. It can be used to verify the identity of the
 * entity that created or signed the manifest.
 *
 * Supports various DID methods including:
 * - did:web (Web DID)
 * - did:key (Key DID)
 * - did:ion (ION DID)
 * - did:ethr (Ethereum DID)
 * - And other W3C compliant DID methods
 */
export class DecentralisedIdentityAssertion extends Assertion {
    public label = AssertionLabels.decentralisedIdentity;
    public uuid = raw.UUIDs.jsonAssertion;

    /**
     * The DID identifier (e.g., "did:web:example.com")
     */
    public did = '';

    /**
     * The resolved DID document
     */
    public didDocument?: DIDDocument;

    /**
     * Resolution metadata from the DID resolution process
     */
    public resolutionMetadata?: {
        contentType?: string;
        retrieved?: string;
        error?: string;
        message?: string;
    };
    assertion!: { id: string };

    /**
     * Whether the DID document has been successfully resolved
     */
    public get isResolved(): boolean {
        return !!this.didDocument && !this.resolutionMetadata?.error;
    }

    public readContentFromJUMBF(box: IBox, claim: Claim): void {
        if (!(box instanceof JSONBox) || !this.uuid || !BinaryHelper.bufEqual(this.uuid, raw.UUIDs.jsonAssertion)) {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'Decentralised identity assertion has invalid type',
            );
        }

        const content = box.content as {
            did: string;
            didDocument?: DIDDocument;
            resolutionMetadata?: Record<string, unknown>;
        };

        if (!content.did || typeof content.did !== 'string') {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'Decentralised identity assertion is missing DID',
            );
        }

        // Validate DID format (basic validation)
        if (!this.validateDIDFormat(content.did)) {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                `Invalid DID format: ${content.did}`,
            );
        }

        this.did = content.did;
        this.didDocument = content.didDocument;
        this.resolutionMetadata = content.resolutionMetadata;

        // Validate DID document if present
        if (this.didDocument) {
            this.validateDIDDocument(this.didDocument);
        }
    }

    public generateJUMBFBoxForContent(): IBox {
        if (!this.did) {
            throw new Error('DID is required');
        }

        if (!this.validateDIDFormat(this.did)) {
            throw new Error(`Invalid DID format: ${this.did}`);
        }

        if (this.didDocument) {
            this.validateDIDDocument(this.didDocument);
        }

        const box = new JSONBox();
        box.content = {
            did: this.did,
            ...(this.didDocument && { didDocument: this.didDocument }),
            ...(this.resolutionMetadata && { resolutionMetadata: this.resolutionMetadata }),
        };

        return box;
    }

    /**
     * Validates DID format according to W3C DID specification
     * @param did - The DID to validate
     * @returns true if valid, false otherwise
     */
    private validateDIDFormat(did: string): boolean {
        // DID format: did:method:method-specific-id
        const didRegex = /^did:[a-z0-9]+:[a-zA-Z0-9._%-]*[a-zA-Z0-9]$/;
        return didRegex.test(did);
    }

    /**
     * Validates the structure of a DID document
     * @param doc - The DID document to validate
     * @throws ValidationError if the document is invalid
     */
    private validateDIDDocument(doc: DIDDocument): void {
        // Validate required fields
        if (!doc.id || typeof doc.id !== 'string') {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'DID document is missing id field',
            );
        }

        if (!this.validateDIDFormat(doc.id)) {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                `DID document has invalid id format: ${doc.id}`,
            );
        }

        // Validate context
        if (!doc['@context']) {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'DID document is missing @context',
            );
        }

        const contexts = Array.isArray(doc['@context']) ? doc['@context'] : [doc['@context']];
        const requiredContext = 'https://www.w3.org/ns/did/v1';
        if (!contexts.includes(requiredContext)) {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                `DID document @context must include ${requiredContext}`,
            );
        }

        // Validate verification methods if present
        if (doc.verificationMethod) {
            if (!Array.isArray(doc.verificationMethod)) {
                throw new ValidationError(
                    ValidationStatusCode.AssertionJSONInvalid,
                    this.sourceBox,
                    'DID document verificationMethod must be an array',
                );
            }

            for (const method of doc.verificationMethod) {
                this.validateVerificationMethod(method);
            }
        }
    }

    /**
     * Validates a verification method
     * @param method - The verification method to validate
     * @throws ValidationError if the method is invalid
     */
    private validateVerificationMethod(method: DIDVerificationMethod): void {
        if (!method.id || typeof method.id !== 'string') {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'Verification method is missing id',
            );
        }

        if (!method.type || typeof method.type !== 'string') {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'Verification method is missing type',
            );
        }

        if (!method.controller || typeof method.controller !== 'string') {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'Verification method is missing controller',
            );
        }

        // Must have either publicKeyJwk or publicKeyMultibase
        if (!method.publicKeyJwk && !method.publicKeyMultibase) {
            throw new ValidationError(
                ValidationStatusCode.AssertionJSONInvalid,
                this.sourceBox,
                'Verification method must have either publicKeyJwk or publicKeyMultibase',
            );
        }
    }

    /**
     * Resolves a DID to its DID document
     * @param did - The DID to resolve
     * @param resolver - Optional custom resolver function
     * @returns Promise resolving to the DID resolution result
     */
    public async resolveDID(
        did?: string,
        resolver?: (did: string) => Promise<DIDResolutionResult>,
    ): Promise<DIDResolutionResult> {
        const targetDID = did ?? this.did;

        if (!targetDID) {
            return {
                didDocument: null,
                didResolutionMetadata: {
                    error: 'invalidDid',
                    message: 'No DID provided',
                },
                didDocumentMetadata: {},
            };
        }

        if (!this.validateDIDFormat(targetDID)) {
            return {
                didDocument: null,
                didResolutionMetadata: {
                    error: 'invalidDid',
                    message: `Invalid DID format: ${targetDID}`,
                },
                didDocumentMetadata: {},
            };
        }

        // Use custom resolver if provided
        if (resolver) {
            const result = await resolver(targetDID);
            if (result.didDocument) {
                this.didDocument = result.didDocument;
                this.resolutionMetadata = result.didResolutionMetadata;
            }
            return result;
        }

        // Default resolution for did:web method
        if (targetDID.startsWith('did:web:')) {
            return await this.resolveWebDID(targetDID);
        }

        // For other DID methods, return unimplemented error
        return {
            didDocument: null,
            didResolutionMetadata: {
                error: 'methodNotSupported',
                message: `No resolver available for DID method: ${targetDID.split(':')[1]}`,
            },
            didDocumentMetadata: {},
        };
    }

    /**
     * Resolves a did:web DID to its document
     * @param did - The did:web identifier
     * @returns Promise resolving to the DID resolution result
     */
    private async resolveWebDID(did: string): Promise<DIDResolutionResult> {
        try {
            // Extract domain from did:web:domain format
            // Support encoded paths: did:web:example.com or did:web:example.com:path:to:doc
            const parts = did.replace('did:web:', '').split(':');

            // Decode domain (handles localhost%3A3000 -> localhost:3000)
            const domain = decodeURIComponent(parts[0]);
            const path = parts.slice(1).join('/');

            // Construct URL
            const protocol = domain.includes('localhost') ? 'http' : 'https';
            const url =
                path ? `${protocol}://${domain}/${path}/did.json` : `${protocol}://${domain}/.well-known/did.json`;

            const response = await fetch(url);

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

            // Validate the resolved document
            try {
                this.validateDIDDocument(didDocument);
            } catch (error) {
                return {
                    didDocument: null,
                    didResolutionMetadata: {
                        error: 'invalidDidDocument',
                        message: error instanceof Error ? error.message : 'Invalid DID document structure',
                    },
                    didDocumentMetadata: {},
                };
            }

            // Verify that the document ID matches the DID
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

            this.didDocument = didDocument;
            this.resolutionMetadata = {
                contentType: response.headers.get('content-type') ?? 'application/json',
                retrieved: new Date().toISOString(),
            };

            return {
                didDocument,
                didResolutionMetadata: {
                    contentType: response.headers.get('content-type') ?? 'application/json',
                },
                didDocumentMetadata: {},
            };
        } catch (error) {
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
     * Extracts verification methods that can be used for assertion
     * @returns Array of verification method IDs
     */
    public getAssertionMethods(): string[] {
        if (!this.didDocument?.assertionMethod) {
            return [];
        }

        return this.didDocument.assertionMethod.map(method => {
            if (typeof method === 'string') {
                return method;
            }
            return method.id;
        });
    }

    /**
     * Gets a specific verification method by its ID
     * @param methodId - The ID of the verification method
     * @returns The verification method or undefined if not found
     */
    public getVerificationMethod(methodId: string): DIDVerificationMethod | undefined {
        if (!this.didDocument?.verificationMethod) {
            return undefined;
        }

        return this.didDocument.verificationMethod.find(method => method.id === methodId);
    }
}
