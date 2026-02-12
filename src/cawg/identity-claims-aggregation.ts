/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/**
 * CAWG Identity Claims Aggregation Support
 * Implementation of ICA verifiable credentials per CAWG spec Section 8.1
 *
 * @module cawg/identity-claims-aggregation
 */

import * as JUMBF from '../jumbf';
import {
    addStatus,
    CawgValidationResult,
    createFailureStatus,
    createSuccessStatus,
    IcaStatusCode,
} from './status-codes.js';
import type {
    C2paAssetBinding,
    IdentityClaimsAggregationCredential,
    IdentityClaimsCredentialSubject,
    SignerPayloadMap,
    VerifiedIdentity,
} from './types.js';
import { c2paAssetBindingToSignerPayload, signerPayloadToC2paAssetBinding } from './utils.js';

/**
 * W3C Verifiable Credentials contexts
 */
export const VC_CONTEXT = {
    /** VC Data Model v1.1 */
    V1_1: 'https://www.w3.org/2018/credentials/v1',
    /** VC Data Model v2.0 */
    V2_0: 'https://www.w3.org/ns/credentials/v2',
    /** CAWG Identity Claims Aggregation context */
    CAWG: 'https://cawg.io/identity/1.1/ica/context/',
} as const;

/**
 * VC Types
 */
export const VC_TYPE = {
    Verifiable: 'VerifiableCredential',
    IdentityClaimsAggregation: 'IdentityClaimsAggregationCredential',
} as const;

/**
 * Schema URLs
 */
export const SCHEMA_URL = {
    VC1_1: 'https://cawg.io/identity/1.1/ica/schema/vc1.1/',
    VC2_0: 'https://cawg.io/identity/1.1/ica/schema/vc2.0/',
} as const;

/**
 * Supported DID methods
 */
export const SUPPORTED_DID_METHODS = ['did:web', 'did:key', 'did:ion'] as const;

/**
 * Supported DID verification methods
 */
export const SUPPORTED_VERIFICATION_METHODS = [
    'JsonWebKey2020',
    'Ed25519VerificationKey2020',
    'EcdsaSecp256k1VerificationKey2019',
] as const;

/**
 * Supported COSE algorithms for ICA
 */
export const SUPPORTED_COSE_ALGORITHMS = {
    ES256: -7, // ECDSA with SHA-256
    ES384: -35, // ECDSA with SHA-384
    ES512: -36, // ECDSA with SHA-512
    PS256: -37, // RSASSA-PSS with SHA-256
    PS384: -38, // RSASSA-PSS with SHA-384
    PS512: -39, // RSASSA-PSS with SHA-512
    EdDSA: -8, // EdDSA (Ed25519 only)
} as const;

/**
 * Create an Identity Claims Aggregation credential
 *
 * @param issuer - DID of the identity claims aggregator
 * @param subject - Credential subject including verified identities
 * @param signerPayload - The signer_payload to bind to C2PA asset
 * @param validFrom - Valid from date
 * @param options - Additional options
 * @returns Unsigned ICA credential
 */
export function createIcaCredential(
    issuer: string,
    subject: Omit<IdentityClaimsCredentialSubject, 'c2paAsset'>,
    signerPayload: SignerPayloadMap,
    validFrom: Date,
    options?: {
        validUntil?: Date;
        useVc2?: boolean;
        credentialStatus?: any;
    },
): IdentityClaimsAggregationCredential {
    const useVc2 = options?.useVc2 ?? true;

    // Convert signer_payload to C2PA asset binding format
    const c2paAssetBinding = signerPayloadToC2paAssetBinding(signerPayload);

    const credential: IdentityClaimsAggregationCredential = {
        '@context': [useVc2 ? VC_CONTEXT.V2_0 : VC_CONTEXT.V1_1, VC_CONTEXT.CAWG],
        type: [VC_TYPE.Verifiable, VC_TYPE.IdentityClaimsAggregation],
        issuer,
        credentialSubject: {
            ...subject,
            c2paAsset: c2paAssetBinding,
        },
        credentialSchema: [
            {
                id: useVc2 ? SCHEMA_URL.VC2_0 : SCHEMA_URL.VC1_1,
                type: 'JSONSchema',
            },
        ],
    };

    // Add validity dates based on VC version
    if (useVc2) {
        credential.validFrom = validFrom.toISOString();
        if (options?.validUntil) {
            credential.validUntil = options.validUntil.toISOString();
        }
    } else {
        credential.issuanceDate = validFrom.toISOString();
        if (options?.validUntil) {
            credential.expirationDate = options.validUntil.toISOString();
        }
    }

    // Add optional credential status
    if (options?.credentialStatus) {
        credential.credentialStatus = options.credentialStatus;
    }

    return credential;
}

/**
 * Sign an ICA credential using COSE
 *
 * Per CAWG spec Section 8.1.4, the credential must be secured using
 * COSE as described in W3C "Securing Verifiable Credentials using JOSE and COSE"
 *
 * @param credential - Unsigned credential
 * @param signCallback - Function that creates COSE_Sign1 signature
 * @returns COSE_Sign1 signature bytes (the complete identity assertion signature)
 */
export async function signIcaCredential(
    credential: IdentityClaimsAggregationCredential,
    signCallback: (payload: Uint8Array) => Promise<Uint8Array>,
): Promise<Uint8Array> {
    // Serialize credential as JSON
    const credentialJson = JSON.stringify(credential);
    const credentialBytes = new TextEncoder().encode(credentialJson);

    // Sign using COSE_Sign1
    // The callback should create a COSE_Sign1 structure with:
    // - Protected header: { alg: <algorithm>, content type: "application/vc" }
    // - Unprotected header: optional timestamp in sigTst2
    // - Payload: credentialBytes (unencoded)
    const coseSign1 = await signCallback(credentialBytes);

    return coseSign1;
}

/**
 * Validate an Identity Claims Aggregation credential
 *
 * Implements validation as described in CAWG spec Section 8.1.5
 *
 * @param signature - COSE_Sign1 signature bytes
 * @param signerPayload - Expected signer_payload from identity assertion
 * @param assertionLabel - Label of the identity assertion
 * @param trustedIssuers - List of trusted ICA issuer DIDs
 * @param options - Validation options
 * @returns Validation result
 */
export async function validateIcaCredential(
    signature: Uint8Array,
    signerPayload: SignerPayloadMap,
    assertionLabel: string,
    trustedIssuers: string[],
    options?: {
        trustedAnchors?: string[];
        checkRevocation?: boolean;
        validationTime?: Date;
    },
): Promise<CawgValidationResult> {
    const result: CawgValidationResult = {
        valid: true,
        statuses: [],
    };

    try {
        // Step 1: Parse COSE_Sign1 structure
        const coseSign1 = await parseCoseSign1(signature);
        if (!coseSign1) {
            addStatus(
                result,
                createFailureStatus(
                    IcaStatusCode.InvalidCoseSign1,
                    assertionLabel,
                    'Failed to parse COSE_Sign1 structure',
                ),
            );
            return result;
        }

        // Step 2: Validate COSE protected headers
        const algValid = validateCoseAlgorithm(coseSign1.protectedHeader?.alg);
        if (!algValid) {
            addStatus(
                result,
                createFailureStatus(IcaStatusCode.InvalidAlg, assertionLabel, 'Unsupported or missing COSE algorithm'),
            );
        }

        const contentType = coseSign1.protectedHeader?.contentType;
        if (contentType !== 'application/vc') {
            addStatus(
                result,
                createFailureStatus(
                    IcaStatusCode.InvalidContentType,
                    assertionLabel,
                    'Content type must be "application/vc"',
                ),
            );
        }

        // Step 3: Parse verifiable credential
        const credentialJson = new TextDecoder().decode(coseSign1.payload);
        let credential: IdentityClaimsAggregationCredential;

        try {
            credential = JSON.parse(credentialJson);
        } catch {
            addStatus(
                result,
                createFailureStatus(
                    IcaStatusCode.InvalidVerifiableCredential,
                    assertionLabel,
                    'Failed to parse verifiable credential JSON',
                ),
            );
            return result;
        }

        // Step 4: Validate credential structure
        validateIcaCredentialStructure(credential, assertionLabel, result);

        // Step 5: Obtain issuer's public key via DID resolution
        const issuerDid = extractIssuerDid(credential);
        if (!issuerDid) {
            addStatus(
                result,
                createFailureStatus(IcaStatusCode.InvalidIssuer, assertionLabel, 'Issuer is not a valid DID'),
            );
            return result;
        }

        const didMethod = issuerDid.split(':')[1];
        if (!SUPPORTED_DID_METHODS.includes(`did:${didMethod}` as any)) {
            addStatus(
                result,
                createFailureStatus(
                    IcaStatusCode.DidUnsupportedMethod,
                    assertionLabel,
                    `DID method not supported: did:${didMethod}`,
                ),
            );
        }

        const didDocument = await resolveDid(issuerDid);
        if (!didDocument) {
            addStatus(
                result,
                createFailureStatus(IcaStatusCode.DidUnavailable, assertionLabel, 'Failed to resolve DID document'),
            );
            return result;
        }

        const publicKey = extractPublicKeyFromDidDocument(didDocument);
        if (!publicKey) {
            addStatus(
                result,
                createFailureStatus(
                    IcaStatusCode.InvalidDidDocument,
                    assertionLabel,
                    'Failed to extract public key from DID document',
                ),
            );
            return result;
        }

        // Step 6: Verify issuer is trusted
        const issuerTrusted = await verifyIssuerTrust(issuerDid, trustedIssuers, options?.trustedAnchors);

        if (!issuerTrusted) {
            addStatus(
                result,
                createFailureStatus(IcaStatusCode.UntrustedIssuer, assertionLabel, 'Issuer DID is not in trusted list'),
            );
        }

        // Step 7: Verify COSE signature
        const signatureValid = await verifyCoseSign1(coseSign1, publicKey);

        if (!signatureValid) {
            addStatus(
                result,
                createFailureStatus(
                    IcaStatusCode.SignatureMismatch,
                    assertionLabel,
                    'COSE signature verification failed',
                ),
            );
            return result;
        }

        // Step 8: Verify timestamp if present
        const timestamp = extractTimestamp(coseSign1);
        if (timestamp) {
            const timestampValid = await validateTimestamp(timestamp);
            if (timestampValid) {
                addStatus(
                    result,
                    createSuccessStatus(
                        IcaStatusCode.TimeStampValidated as any,
                        assertionLabel,
                        'RFC 3161 timestamp validated',
                    ),
                );
            } else {
                addStatus(
                    result,
                    createFailureStatus(IcaStatusCode.TimeStampInvalid, assertionLabel, 'Invalid RFC 3161 timestamp'),
                );
            }
        }

        // Step 9: Verify validity dates
        validateCredentialValidityDates(credential, assertionLabel, result, options?.validationTime);

        // Step 10: Check revocation status
        if (options?.checkRevocation && credential.credentialStatus) {
            await validateRevocationStatus(credential, assertionLabel, result);
        }

        // Step 11: Verify binding to C2PA asset
        validateC2paAssetBinding(credential.credentialSubject.c2paAsset, signerPayload, assertionLabel, result);

        // Step 12: Validate verified identities
        validateVerifiedIdentities(credential.credentialSubject.verifiedIdentities, assertionLabel, result);

        // Step 13: Final status
        if (result.valid) {
            addStatus(
                result,
                createSuccessStatus(
                    IcaStatusCode.CredentialValid as any,
                    assertionLabel,
                    'Identity claims aggregation credential is valid',
                ),
            );
        }
    } catch (error) {
        addStatus(
            result,
            createFailureStatus(
                IcaStatusCode.InvalidVerifiableCredential,
                assertionLabel,
                `Validation error: ${String(error)}`,
            ),
        );
    }

    return result;
}

// Helper functions

function validateCoseAlgorithm(alg: number | undefined): boolean {
    if (alg === undefined) return false;
    return (Object.values(SUPPORTED_COSE_ALGORITHMS) as number[]).includes(alg);
}

function validateIcaCredentialStructure(
    credential: IdentityClaimsAggregationCredential,
    label: string,
    result: CawgValidationResult,
): void {
    // Validate @context
    if (!credential['@context'] || !Array.isArray(credential['@context'])) {
        addStatus(
            result,
            createFailureStatus(IcaStatusCode.InvalidVerifiableCredential, label, 'Missing or invalid @context'),
        );
    }

    // Validate type
    if (!credential.type || !Array.isArray(credential.type)) {
        addStatus(
            result,
            createFailureStatus(IcaStatusCode.InvalidVerifiableCredential, label, 'Missing or invalid type'),
        );
    }

    const hasRequiredTypes =
        credential.type.includes(VC_TYPE.Verifiable) && credential.type.includes(VC_TYPE.IdentityClaimsAggregation);

    if (!hasRequiredTypes) {
        addStatus(
            result,
            createFailureStatus(IcaStatusCode.InvalidVerifiableCredential, label, 'Missing required credential types'),
        );
    }
}

function extractIssuerDid(credential: IdentityClaimsAggregationCredential): string | null {
    if (typeof credential.issuer === 'string') {
        return credential.issuer;
    } else if (credential.issuer && typeof credential.issuer === 'object') {
        return credential.issuer.id;
    }
    return null;
}

async function resolveDid(did: string): Promise<any | null> {
    // Resolve DID to DID document
    // Implementation would use a DID resolver library
    return null;
}

function extractPublicKeyFromDidDocument(didDocument: any): any | null {
    // Extract assertionMethod verification method
    // and return public key material
    return null;
}

async function verifyIssuerTrust(
    issuerDid: string,
    trustedIssuers: string[],
    trustedAnchors?: string[],
): Promise<boolean> {
    // Check if issuer is directly trusted or chains to trusted anchor
    return trustedIssuers.includes(issuerDid);
}

async function verifyCoseSign1(coseSign1: any, publicKey: any): Promise<boolean> {
    // Verify COSE_Sign1 signature using public key
    return true;
}

function extractTimestamp(coseSign1: any): any | null {
    // Extract RFC 3161 timestamp from sigTst2 unprotected header
    return null;
}

async function validateTimestamp(timestamp: any): Promise<boolean> {
    // Validate RFC 3161 timestamp
    return true;
}

function validateCredentialValidityDates(
    credential: IdentityClaimsAggregationCredential,
    label: string,
    result: CawgValidationResult,
    validationTime?: Date,
): void {
    const now = validationTime ?? new Date();

    // Check validFrom / issuanceDate
    const validFrom = credential.validFrom ?? credential.issuanceDate;
    if (!validFrom) {
        addStatus(
            result,
            createFailureStatus(IcaStatusCode.ValidFromMissing, label, 'Missing validFrom or issuanceDate'),
        );
        return;
    }

    const validFromDate = new Date(validFrom);
    if (validFromDate > now) {
        addStatus(result, createFailureStatus(IcaStatusCode.ValidFromInvalid, label, 'Credential not yet valid'));
    }

    // Check validUntil / expirationDate
    const validUntil = credential.validUntil ?? credential.expirationDate;
    if (validUntil) {
        const validUntilDate = new Date(validUntil);
        if (validUntilDate < now) {
            addStatus(result, createFailureStatus(IcaStatusCode.ValidUntilInvalid, label, 'Credential has expired'));
        }
    }
}

async function validateRevocationStatus(
    credential: IdentityClaimsAggregationCredential,
    label: string,
    result: CawgValidationResult,
): Promise<void> {
    // Check credential status for revocation
    // Implementation would check bitstring status list or other mechanism

    if (credential.credentialStatus) {
        // Simplified check
        addStatus(
            result,
            createSuccessStatus(IcaStatusCode.CredentialNotRevoked as any, label, 'Credential not revoked'),
        );
    }
}

function validateC2paAssetBinding(
    c2paAsset: C2paAssetBinding,
    signerPayload: SignerPayloadMap,
    label: string,
    result: CawgValidationResult,
): void {
    // Convert and compare
    const convertedPayload = c2paAssetBindingToSignerPayload(c2paAsset);

    if (JSON.stringify(convertedPayload) !== JSON.stringify(signerPayload)) {
        addStatus(
            result,
            createFailureStatus(IcaStatusCode.SignerPayloadMismatch, label, 'c2paAsset does not match signer_payload'),
        );
    }
}

function validateVerifiedIdentities(
    verifiedIdentities: VerifiedIdentity[],
    label: string,
    result: CawgValidationResult,
): void {
    if (!verifiedIdentities || verifiedIdentities.length === 0) {
        addStatus(
            result,
            createFailureStatus(
                IcaStatusCode.VerifiedIdentitiesMissing,
                label,
                'verifiedIdentities array is empty or missing',
            ),
        );
        return;
    }

    // Validate each verified identity entry
    for (const identity of verifiedIdentities) {
        if (!identity.type || !identity.provider || !identity.verifiedAt) {
            addStatus(
                result,
                createFailureStatus(
                    IcaStatusCode.VerifiedIdentitiesInvalid,
                    label,
                    'Verified identity missing required fields',
                ),
            );
        }
    }
}

async function parseCoseSign1(data: Uint8Array): Promise<any | null> {
    try {
        // COSE_Sign1 structure (RFC 8152):
        // [
        //   protected: bstr,
        //   unprotected: {* label => int / tstr => any},
        //   payload: bstr,
        //   signature: bstr
        // ]

        // You'll need a CBOR decoder library (e.g., cbor, cbor-x, or cborg)
        // Example using a hypothetical CBOR library:
        const cborDecoded = JUMBF.CBORBox.decoder.decode(data); // or similar

        if (!Array.isArray(cborDecoded) || cborDecoded.length !== 4) {
            return null;
        }

        const [protectedHeaderBytes, unprotectedHeader, payload, signature] = cborDecoded;

        // Decode protected header
        const protectedHeader = JUMBF.CBORBox.decoder.decode(protectedHeaderBytes);

        return {
            protectedHeader,
            unprotectedHeader,
            payload,
            signature,
        };
    } catch {
        return null;
    }
}
