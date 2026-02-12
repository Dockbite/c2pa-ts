/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/**
 * CAWG X.509 Certificate and COSE Signature Support
 * Implementation of X.509/COSE-based identity assertions per CAWG spec Section 8.2
 *
 * @module cawg/x509-cose
 */

import { ValidationStatusCode } from '../manifest/types.js';
import { ValidationResult } from '../manifest/ValidationResult.js';
import { CawgTrustConfiguration, SignerPayloadMap, TrustDecision } from './types.js';
import { serializeSignerPayload } from './utils.js';

/**
 * Extended Key Usage OIDs
 */
export const EKU_OID = {
    /** Document signing */
    DocumentSigning: '1.3.6.1.5.5.7.3.36',
    /** Email protection (S/MIME) */
    EmailProtection: '1.3.6.1.5.5.7.3.4',
} as const;

/**
 * Certificate Policy OIDs for S/MIME certificates
 * Valid only until March 31, 2027 per CAWG spec Section 8.2.4.1
 */
export const SMIME_CERTIFICATE_POLICY = {
    /** Organization-validated Multipurpose */
    OrgValidatedMultipurpose: '2.23.140.1.5.2.2',
    /** Organization-validated Strict */
    OrgValidatedStrict: '2.23.140.1.5.2.3',
    /** Sponsor-validated Multipurpose */
    SponsorValidatedMultipurpose: '2.23.140.1.5.3.2',
    /** Sponsor-validated Strict */
    SponsorValidatedStrict: '2.23.140.1.5.3.3',
    /** Individual-validated Multipurpose */
    IndividualValidatedMultipurpose: '2.23.140.1.5.4.2',
    /** Individual-validated Strict */
    IndividualValidatedStrict: '2.23.140.1.5.4.3',
} as const;

/**
 * Default CAWG trust configuration
 */
export function createDefaultTrustConfiguration(): CawgTrustConfiguration {
    const config: CawgTrustConfiguration = {
        acceptedEkus: [EKU_OID.DocumentSigning],
        acceptedCertificatePolicies: new Map(),
        trustAnchors: [],
    };

    // Add interim S/MIME EKU support (valid until March 31, 2027)
    config.acceptedEkus.push(EKU_OID.EmailProtection);
    config.acceptedCertificatePolicies.set(EKU_OID.EmailProtection, [
        SMIME_CERTIFICATE_POLICY.OrgValidatedMultipurpose,
        SMIME_CERTIFICATE_POLICY.OrgValidatedStrict,
        SMIME_CERTIFICATE_POLICY.SponsorValidatedMultipurpose,
        SMIME_CERTIFICATE_POLICY.SponsorValidatedStrict,
        SMIME_CERTIFICATE_POLICY.IndividualValidatedMultipurpose,
        SMIME_CERTIFICATE_POLICY.IndividualValidatedStrict,
    ]);

    return config;
}

/**
 * Create a COSE signature for an identity assertion
 *
 * This follows the C2PA signing process adapted for identity assertions
 * as described in CAWG spec Section 8.2.1
 *
 * @param signerPayload - The signer_payload to sign
 * @param signCallback - Function that creates the COSE signature
 * @param includeTimeStamp - Whether to include an RFC 3161 timestamp
 * @returns COSE signature bytes
 */
export async function createCoseSignature(
    signerPayload: SignerPayloadMap,
    signCallback: (data: Uint8Array) => Promise<Uint8Array>,
    includeTimeStamp = true,
): Promise<Uint8Array> {
    // Serialize signer_payload using CBOR deterministic encoding
    const serialized = serializeSignerPayload(signerPayload);

    // Create COSE_Sign1 signature
    // The actual signing is delegated to the callback which should:
    // 1. Create COSE_Sign1 structure
    // 2. Include X.509 certificates
    // 3. Optionally add RFC 3161 timestamp (v2 only)
    // 4. Optionally add credential revocation information (OCSP)
    const signature = await signCallback(serialized);

    return signature;
}

/**
 * Validate a COSE signature for an identity assertion
 *
 * This follows the C2PA validation process adapted for identity assertions
 * as described in CAWG spec Section 8.2.2
 *
 * @param signerPayload - The signer_payload structure
 * @param signature - The COSE signature to validate
 * @param assertionLabel - Label of the identity assertion
 * @param trustConfig - Trust configuration
 * @param validationTime - Time of validation (for checking certificate validity)
 * @returns Validation result
 */
export async function validateCoseSignature(
    signerPayload: SignerPayloadMap,
    signature: Uint8Array,
    assertionLabel: string,
    sourceBox: JUMBF.SuperBox,
    trustConfig: CawgTrustConfiguration,
    validationTime?: Date,
): Promise<ValidationResult> {
    const result: ValidationResult = new ValidationResult();

    try {
        // Parse COSE_Sign1 structure
        const coseSign1 = await parseCoseSign1(signature);

        // Extract certificate chain
        const certificates = extractCertificates(coseSign1);
        if (certificates.length === 0) {
            result.addError(
                ValidationStatusCode.CredentialRevoked,
                sourceBox,
                'No certificates found in COSE signature',
            );
            return result;
        }

        const endEntityCert = certificates[0];

        // Verify certificate chain
        const chainValid = await verifyCertificateChain(certificates, trustConfig.trustAnchors, validationTime);

        if (!chainValid) {
            result.addError(ValidationStatusCode.CredentialRevoked, sourceBox, 'Certificate chain validation failed');
            return result;
        }

        // Check Extended Key Usage
        const ekuValid = await validateExtendedKeyUsage(endEntityCert, trustConfig.acceptedEkus, validationTime);

        if (!ekuValid) {
            result.addError(
                ValidationStatusCode.CredentialRevoked,
                sourceBox,
                'Certificate does not have required Extended Key Usage',
            );
        }

        // Check Certificate Policies (if required for this EKU)
        const certPolicies = extractCertificatePolicies(endEntityCert);
        const ekus = extractExtendedKeyUsage(endEntityCert);

        for (const eku of ekus) {
            const requiredPolicies = trustConfig.acceptedCertificatePolicies.get(eku);
            if (requiredPolicies) {
                const policyValid = certPolicies.some(cp => requiredPolicies.includes(cp));

                if (!policyValid) {
                    result.addError(
                        ValidationStatusCode.CredentialRevoked,
                        sourceBox,
                        `Certificate does not have required policy for EKU ${eku}`,
                    );
                }
            }
        }

        // Verify signature
        const serialized = serializeSignerPayload(signerPayload);
        const signatureValid = await verifyCoseSignature(coseSign1, serialized, endEntityCert);

        if (!signatureValid) {
            result.addError(ValidationStatusCode.CredentialRevoked, sourceBox, 'COSE signature verification failed');
            return result;
        }

        // Check for timestamp (v2 only)
        const timestamp = extractTimestamp(coseSign1);
        if (timestamp?.version === 2) {
            const timestampValid = await validateTimestamp(timestamp);
            if (timestampValid) {
                result.addInformational(
                    ValidationStatusCode.TimeStampValidated,
                    sourceBox,
                    'RFC 3161 v2 timestamp validated',
                );
            } else {
                result.addError(
                    ValidationStatusCode.TimestampInvalid,
                    sourceBox,
                    'RFC 3161 timestamp validation failed',
                );
            }
        } else if (timestamp?.version === 1) {
            // v1 timestamps are not allowed
            result.addError(
                ValidationStatusCode.TimestampInvalid,
                sourceBox,
                'v1 timestamps are not allowed in identity assertions',
            );
        }

        // Check revocation status
        const revoked = await checkRevocationStatus(endEntityCert, coseSign1, validationTime);

        if (revoked) {
            result.addError(ValidationStatusCode.CredentialRevoked, sourceBox, 'Certificate was revoked');
            return result;
        }

        // Determine trust decision
        const trustDecision = determineTrustDecision(endEntityCert, trustConfig.trustAnchors);

        if (trustDecision === TrustDecision.Trusted) {
            result.addInformational(
                ValidationStatusCode.Trusted,
                sourceBox,
                'Identity assertion validated and trusted',
            );
        } else {
            result.addInformational(
                ValidationStatusCode.WellFormed,
                sourceBox,
                'Identity assertion validated but not trusted',
            );
        }
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        result.addError(ValidationStatusCode.ValidationError, sourceBox, `Validation error: ${errorMessage}`);
    }

    return result;
}

/**
 * Extract logo/icon from X.509 certificate
 *
 * Per CAWG spec Section 8.2.3, look for RFC 9399 logotype extension
 *
 * @param certificate - DER-encoded X.509 certificate
 * @returns Logo image data (if found)
 */
export async function extractCertificateLogo(
    certificate: Uint8Array,
): Promise<{ data: Uint8Array; mimeType: string } | null> {
    try {
        // Parse certificate and look for logotype extension
        // OID: 1.3.6.1.5.5.7.1.12
        const logoExtension = findCertificateExtension(certificate, '1.3.6.1.5.5.7.1.12');

        if (!logoExtension) {
            return null;
        }

        // Parse logotype structure per RFC 9399
        // This is a simplified version
        return null; // Implementation would parse the logotype data
    } catch {
        return null;
    }
}

/**
 * Check if interim S/MIME trust model applies
 * Valid only for identity assertions created on or before March 31, 2027
 */
export function isInterimTrustModelValid(assertionCreationTime: Date): boolean {
    const cutoffDate = new Date('2027-03-31T23:59:59Z');
    return assertionCreationTime <= cutoffDate;
}

// Helper functions (simplified implementations)

async function parseCoseSign1(data: Uint8Array): Promise<any> {
    // Parse COSE_Sign1 structure
    // Implementation would use a COSE library
    return {};
}

function extractCertificates(coseSign1: any): Uint8Array[] {
    // Extract X.509 certificates from COSE structure
    return [];
}

async function verifyCertificateChain(
    certificates: Uint8Array[],
    trustAnchors: Uint8Array[],
    validationTime?: Date,
): Promise<boolean> {
    // Verify certificate chain up to trust anchor
    return true;
}

async function validateExtendedKeyUsage(
    certificate: Uint8Array,
    acceptedEkus: string[],
    validationTime?: Date,
): Promise<boolean> {
    const ekus = extractExtendedKeyUsage(certificate);
    return ekus.some(eku => acceptedEkus.includes(eku));
}

function extractExtendedKeyUsage(certificate: Uint8Array): string[] {
    // Extract EKU OIDs from certificate
    return [];
}

function extractCertificatePolicies(certificate: Uint8Array): string[] {
    // Extract certificate policy OIDs
    return [];
}

async function verifyCoseSignature(coseSign1: any, data: Uint8Array, certificate: Uint8Array): Promise<boolean> {
    // Verify COSE signature
    return true;
}

function extractTimestamp(coseSign1: any): { version: number; data: any } | null {
    // Extract RFC 3161 timestamp from sigTst2 header
    return null;
}

async function validateTimestamp(timestamp: any): Promise<boolean> {
    // Validate RFC 3161 timestamp
    return true;
}

async function checkRevocationStatus(certificate: Uint8Array, coseSign1: any, validationTime?: Date): Promise<boolean> {
    // Check OCSP or CRL for revocation
    return false; // Not revoked
}

function determineTrustDecision(certificate: Uint8Array, trustAnchors: Uint8Array[]): TrustDecision {
    // Determine if certificate chains to a trusted anchor
    return TrustDecision.WellFormed;
}

function findCertificateExtension(certificate: Uint8Array, oid: string): Uint8Array | null {
    // Find and extract certificate extension by OID
    return null;
}
