/**
 * CAWG Identity Assertion Module
 *
 * Implementation of the Creator Assertions Working Group (CAWG) Identity Assertion
 * specification version 1.2 (DIF Ratified - December 15, 2025)
 *
 * This module provides comprehensive support for creating and validating identity
 * assertions in C2PA manifests, allowing named actors to cryptographically bind
 * their identity to digital assets.
 *
 * @module cawg
 *
 * @example Creating an identity assertion
 * ```typescript
 * import { createSignerPayload, createIdentityAssertion } from '@trustnxt/c2pa-ts/cawg';
 *
 * const signerPayload = createSignerPayload({
 *   referencedAssertions: [
 *     // Include hard binding and other assertions
 *   ],
 *   sigType: 'cawg.x509.cose',
 *   roles: ['cawg.creator'],
 * });
 *
 * // Get signature from credential holder
 * const signature = await signPayload(signerPayload);
 *
 * const assertion = createIdentityAssertion(signerPayload, signature);
 * ```
 *
 * @example Validating an identity assertion
 * ```typescript
 * import { validateIdentityAssertion } from '@trustnxt/c2pa-ts/cawg';
 *
 * const result = await validateIdentityAssertion(
 *   assertionData,
 *   'cawg.identity',
 *   claimData,
 *   { checkRevocation: true }
 * );
 *
 * if (result.valid) {
 *   console.log('Identity assertion is valid');
 * }
 * ```
 */

// Type definitions
export * from './types.js';

// Status codes and validation results
export * from './status-codes.js';

// Utility functions
export * from './utils.js';

// Creator functions
export {
    createSignerPayload,
    createIdentityAssertionWithSigning,
    createPlaceholderAssertion,
    calculateExpectedPartialClaim,
    calculateExpectedClaimGenerator,
    validateReferencedAssertions,
    generateAssertionLabel,
} from './creator.js';

// Validator functions
export { validateIdentityAssertion, isWellFormedIdentityAssertion } from './validator.js';

// X.509/COSE support
export {
    createCoseSignature,
    validateCoseSignature,
    extractCertificateLogo,
    isInterimTrustModelValid,
    createDefaultTrustConfiguration,
    EKU_OID,
    SMIME_CERTIFICATE_POLICY,
} from './x509-cose.js';

// Identity Claims Aggregation support
export {
    createIcaCredential,
    signIcaCredential,
    validateIcaCredential,
    VC_CONTEXT,
    VC_TYPE,
    SCHEMA_URL,
    SUPPORTED_DID_METHODS,
    SUPPORTED_VERIFICATION_METHODS,
    SUPPORTED_COSE_ALGORITHMS,
} from './identity-claims-aggregation.js';

/**
 * CAWG specification version implemented by this module
 */
export const CAWG_VERSION = '1.2';

/**
 * CAWG specification release date
 */
export const CAWG_RELEASE_DATE = '2025-12-15';

/**
 * Default identity assertion label
 */
export const DEFAULT_ASSERTION_LABEL = 'cawg.identity';

/**
 * Maximum length for text strings in CAWG structures
 */
export const MAX_TSTR_LENGTH = 4096;
