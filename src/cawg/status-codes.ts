/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * CAWG Identity Assertion Status Codes
 * Validation result codes as defined in CAWG specification v1.2, Section 7.2
 *
 * @module cawg/status-codes
 */

/**
 * Base interface for validation status
 */
export interface ValidationStatus {
    /** Status code identifier */
    code: string;
    /** URL/label of the identity assertion */
    url: string;
    /** Whether this is a success or failure status */
    success: boolean;
    /** Optional human-readable explanation */
    explanation?: string;
}

/**
 * Success status codes
 */
export enum SuccessCode {
    /** The identity assertion is validated and trusted */
    Trusted = 'cawg.identity.trusted',
    /** The identity assertion is well-formed but not trusted */
    WellFormed = 'cawg.identity.well-formed',
}

/**
 * General failure codes for identity assertions
 */
export enum FailureCode {
    /** The CBOR of the identity assertion is not valid */
    CborInvalid = 'cawg.identity.cbor.invalid',
    /** Referenced assertion could not be found in the C2PA claim */
    AssertionMismatch = 'cawg.identity.assertion.mismatch',
    /** Identity assertion contains duplicate assertion references */
    AssertionDuplicate = 'cawg.identity.assertion.duplicate',
    /** Identity assertion was signed using a revoked credential */
    CredentialRevoked = 'cawg.identity.credential_revoked',
    /** Identity assertion does not reference a hard binding assertion */
    HardBindingMissing = 'cawg.identity.hard_binding_missing',
    /** Identity assertion does not reference the correct hard binding assertion */
    HardBindingIncorrect = 'cawg.identity.hard_binding_incorrect',
    /** The sig_type is not recognized */
    SigTypeUnknown = 'cawg.identity.sig_type.unknown',
    /** Pad field contains non-zero bytes */
    PadInvalid = 'cawg.identity.pad.invalid',
    /** The expected_partial_claim field did not match */
    ExpectedPartialClaimMismatch = 'cawg.identity.expected_partial_claim.mismatch',
    /** The expected_claim_generator field did not match */
    ExpectedClaimGeneratorMismatch = 'cawg.identity.expected_claim_generator.mismatch',
    /** Unexpected identity assertion exists in the manifest */
    UnexpectedCountersigner = 'cawg.identity.unexpected_countersigner',
    /** Identity assertion has different signing credentials than expected */
    ExpectedCountersignerMismatch = 'cawg.identity.expected_countersigner.mismatch',
    /** Expected identity assertion is missing from the manifest */
    ExpectedCountersignerMissing = 'cawg.identity.expected_countersigner.missing',
}

/**
 * Identity Claims Aggregation (ICA) specific status codes
 */
export enum IcaStatusCode {
    /** The ICA credential has passed all validation requirements */
    CredentialValid = 'cawg.ica.credential_valid',
    /** The signature could not be parsed as valid COSE_Sign1 */
    InvalidCoseSign1 = 'cawg.ica.invalid_cose_sign1',
    /** The alg header is missing or unsupported */
    InvalidAlg = 'cawg.ica.invalid_alg',
    /** The content type header is missing or incorrect */
    InvalidContentType = 'cawg.ica.invalid_content_type',
    /** The payload is not a valid Verifiable Credential */
    InvalidVerifiableCredential = 'cawg.ica.invalid_verifiable_credential',
    /** The issuer field is not a DID */
    InvalidIssuer = 'cawg.ica.invalid_issuer',
    /** The issuer DID uses an unsupported method */
    DidUnsupportedMethod = 'cawg.ica.did_unsupported_method',
    /** Unable to resolve the DID document */
    DidUnavailable = 'cawg.ica.did_unavailable',
    /** DID document could not be parsed */
    InvalidDidDocument = 'cawg.ica.invalid_did_document',
    /** DID is from an untrusted source */
    UntrustedIssuer = 'cawg.ica.untrusted_issuer',
    /** Signature is not valid */
    SignatureMismatch = 'cawg.ica.signature_mismatch',
    /** Valid RFC 3161 timestamp found */
    TimeStampValidated = 'cawg.ica.time_stamp.validated',
    /** Invalid RFC 3161 timestamp found */
    TimeStampInvalid = 'cawg.ica.time_stamp.invalid',
    /** Missing issuanceDate or validFrom field */
    ValidFromMissing = 'cawg.ica.valid_from.missing',
    /** Invalid issuanceDate or validFrom value */
    ValidFromInvalid = 'cawg.ica.valid_from.invalid',
    /** Invalid expirationDate or validUntil value */
    ValidUntilInvalid = 'cawg.ica.valid_until.invalid',
    /** Unsupported revocation method */
    RevocationUnsupported = 'cawg.ica.revocation.unsupported',
    /** Revocation status unavailable */
    RevocationUnavailable = 'cawg.ica.revocation.unavailable',
    /** Credential verified as not revoked */
    CredentialNotRevoked = 'cawg.ica.credential.not_revoked',
    /** Credential was found to be revoked */
    CredentialRevoked = 'cawg.ica.credential.revoked',
    /** c2paAsset field does not match signer_payload */
    SignerPayloadMismatch = 'cawg.ica.signer_payload.mismatch',
    /** verifiedIdentities field is missing */
    VerifiedIdentitiesMissing = 'cawg.ica.verified_identities.missing',
    /** One or more verifiedIdentities entries is invalid */
    VerifiedIdentitiesInvalid = 'cawg.ica.verified_identities.invalid',
}

/**
 * Create a success validation status
 */
export function createSuccessStatus(code: SuccessCode, url: string, explanation?: string): ValidationStatus {
    return {
        code,
        url,
        success: true,
        explanation,
    };
}

/**
 * Create a failure validation status
 */
export function createFailureStatus(
    code: FailureCode | IcaStatusCode | string,
    url: string,
    explanation?: string,
): ValidationStatus {
    return {
        code,
        url,
        success: false,
        explanation,
    };
}

/**
 * Validation result containing all status entries
 */
export interface CawgValidationResult {
    /** Whether overall validation passed */
    valid: boolean;
    /** List of all validation statuses */
    statuses: ValidationStatus[];
    /** Parsed identity assertion (if valid) */
    identityAssertion?: any;
}

/**
 * Add a status to a validation result
 */
export function addStatus(result: CawgValidationResult, status: ValidationStatus): void {
    result.statuses.push(status);
    if (!status.success) {
        result.valid = false;
    }
}

/**
 * Check if a validation result has any failure codes
 */
export function hasFailures(result: CawgValidationResult): boolean {
    return result.statuses.some(s => !s.success);
}

/**
 * Get all failure statuses from a validation result
 */
export function getFailures(result: CawgValidationResult): ValidationStatus[] {
    return result.statuses.filter(s => !s.success);
}

/**
 * Get all success statuses from a validation result
 */
export function getSuccesses(result: CawgValidationResult): ValidationStatus[] {
    return result.statuses.filter(s => s.success);
}

/**
 * Check if a specific status code is present
 */
export function hasStatusCode(result: CawgValidationResult, code: string): boolean {
    return result.statuses.some(s => s.code === code);
}
