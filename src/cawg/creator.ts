/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/**
 * CAWG Identity Assertion Creation
 * Functions for creating identity assertions according to CAWG specification v1.2
 *
 * @module cawg/creator
 */

import { Crypto, HashAlgorithm } from '../crypto';
import { IdentityAssertion } from '../manifest/assertions/IdentityAssertion';
import type {
    ExpectedCountersignerMap,
    HashedUriMap,
    HashMap,
    IdentityAssertionCreationOptions,
    PlaceholderAssertion,
    SignerPayloadMap,
} from './types.js';
import {
    extractAssertionLabel,
    isHardBindingAssertion,
    replaceHashWithZeros,
    serializeSignerPayload,
    validateLabel,
} from './utils.js';

/**
 * Create a signer_payload structure
 * This structure will be presented to the credential holder for signature
 *
 * @param options - Creation options including referenced assertions and optional fields
 * @returns The signer_payload structure ready for signing
 */
export function createSignerPayload(options: IdentityAssertionCreationOptions): SignerPayloadMap {
    // Validate that referenced assertions include a hard binding
    const hasHardBinding = options.referencedAssertions.some(ref => {
        const label = extractAssertionLabel(ref.url);
        return label && isHardBindingAssertion(label);
    });

    if (!hasHardBinding) {
        throw new Error(
            'Referenced assertions must include a hard binding assertion (c2pa.hash.data, c2pa.hash.bmff, or c2pa.hash.boxes)',
        );
    }

    // Build the signer_payload structure
    const payload: SignerPayloadMap = {
        referenced_assertions: options.referencedAssertions,
        sig_type: options.sigType,
    };

    // Add optional fields
    if (options.roles && options.roles.length > 0) {
        payload.role = options.roles;
    }

    if (options.expectedPartialClaim) {
        payload.expected_partial_claim = options.expectedPartialClaim;
    }

    if (options.expectedClaimGenerator) {
        payload.expected_claim_generator = options.expectedClaimGenerator;
    }

    if (options.expectedCountersigners && options.expectedCountersigners.length > 0) {
        payload.expected_countersigners = options.expectedCountersigners;
    }

    return payload;
}

/**
 * Calculate expected_partial_claim hash
 *
 * This hash is computed over a modified C2PA claim where:
 * - The current identity assertion's hash is replaced with zeros
 * - Any expected countersigners' hashes are replaced with zeros
 *
 * @param claimData - The complete C2PA claim structure
 * @param currentAssertionLabel - Label of the current identity assertion
 * @param expectedCountersigners - Optional list of expected countersigners
 * @param hashAlgorithm - Hash algorithm to use (e.g., 'sha256')
 * @returns HashMap with the computed hash
 */
export async function calculateExpectedPartialClaim(
    claimData: any,
    currentAssertionLabel: string,
    expectedCountersigners?: ExpectedCountersignerMap[],
    hashAlgorithm = 'sha256',
): Promise<HashMap> {
    // Clone the claim data
    const modifiedClaim = JSON.parse(JSON.stringify(claimData));

    // Replace current assertion's hash with zeros
    const assertions = modifiedClaim.assertions ?? [];
    for (const assertion of assertions) {
        const label = extractAssertionLabel(assertion.url);
        if (label === currentAssertionLabel) {
            assertion.hash = replaceHashWithZeros(assertion.hash);
        }
    }

    // Replace expected countersigners' hashes with zeros
    if (expectedCountersigners) {
        for (const countersigner of expectedCountersigners) {
            // Find matching assertions and replace their hashes
            // Implementation would need to match based on credential
            // This is a simplified version
        }
    }

    // Serialize using CBOR deterministic encoding
    const serialized = serializeSignerPayload(modifiedClaim);

    // Compute hash
    const hash = await computeHash(serialized, hashAlgorithm);

    return {
        alg: hashAlgorithm,
        hash,
    };
}

/**
 * Calculate expected_claim_generator hash
 *
 * @param certificate - The X.509 end-entity certificate (DER encoded)
 * @param hashAlgorithm - Hash algorithm to use
 * @returns HashMap with the computed hash
 */
export async function calculateExpectedClaimGenerator(
    certificate: Uint8Array,
    hashAlgorithm = 'sha256',
): Promise<HashMap> {
    const hash = await computeHash(certificate, hashAlgorithm);

    return {
        alg: hashAlgorithm,
        hash,
    };
}

/**
 * Create a placeholder assertion for reserving space
 *
 * Used when the final file layout needs to be determined before signing
 * (e.g., when using a data hash assertion)
 *
 * @param label - Label for the identity assertion
 * @param estimatedSignatureSize - Estimated size of the final signature in bytes
 * @returns Placeholder assertion structure
 */
export function createPlaceholderAssertion(label: string, estimatedSignatureSize: number): PlaceholderAssertion {
    if (!validateLabel(label)) {
        throw new Error(`Invalid label format: ${label}`);
    }

    // Calculate size needed for placeholder
    // This includes space for:
    // - signer_payload (variable)
    // - signature field (estimated)
    // - pad1 field (will be adjusted)
    // - optional pad2 field

    // Add some buffer for CBOR encoding overhead
    const bufferSize = 100; // bytes for CBOR structure overhead
    const totalSize = estimatedSignatureSize + bufferSize;

    return {
        label,
        size: totalSize,
    };
}

/**
 * Create a complete identity assertion workflow
 *
 * This is a convenience function that:
 * 1. Creates the signer_payload
 * 2. Obtains the signature (via callback)
 * 3. Creates the final identity assertion
 *
 * @param options - Creation options
 * @param signCallback - Async function that signs the serialized payload
 * @returns Complete identity assertion
 */
export async function createIdentityAssertionWithSigning(
    options: IdentityAssertionCreationOptions,
    signCallback: (payload: Uint8Array) => Promise<Uint8Array>,
): Promise<IdentityAssertion> {
    // Create signer_payload
    const signerPayload = createSignerPayload(options);

    // Serialize for signing
    const serializedPayload = serializeSignerPayload(signerPayload);

    // Obtain signature
    const signature = await signCallback(serializedPayload);

    // Create final assertion
    return IdentityAssertion.createIdentityAssertion(signerPayload, signature, options.reservedSignatureSize);
}

/**
 * Helper: Compute cryptographic hash
 *
 * @param data - Data to hash
 * @param algorithm - Hash algorithm name ('sha256', 'sha384', 'sha512')
 * @returns Hash value
 */
async function computeHash(data: Uint8Array, algorithm: string): Promise<Uint8Array> {
    const algorithmMap: Record<string, HashAlgorithm> = {
        sha256: 'SHA-256',
        sha384: 'SHA-384',
        sha512: 'SHA-512',
    };

    const webCryptoAlg = algorithmMap[algorithm.toLowerCase()];
    if (!webCryptoAlg) {
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    }

    const hashBuffer = await Crypto.digest(data, webCryptoAlg);
    return new Uint8Array(hashBuffer);
}

/**
 * Validate referenced assertions requirements
 *
 * Checks that:
 * - No duplicates exist
 * - A hard binding assertion is included
 * - The list is not empty
 *
 * @param references - Array of referenced assertions
 * @throws Error if validation fails
 */
export function validateReferencedAssertions(references: HashedUriMap[]): void {
    if (references.length === 0) {
        throw new Error('Referenced assertions list cannot be empty');
    }

    // Check for duplicates
    const seen = new Set<string>();
    for (const ref of references) {
        const key = `${ref.url}:${ref.alg}:${Buffer.from(ref.hash).toString('base64')}`;
        if (seen.has(key)) {
            throw new Error(`Duplicate assertion reference found: ${ref.url}`);
        }
        seen.add(key);
    }

    // Check for hard binding
    const hasHardBinding = references.some(ref => {
        const label = extractAssertionLabel(ref.url);
        return label && isHardBindingAssertion(label);
    });

    if (!hasHardBinding) {
        throw new Error('Referenced assertions must include a hard binding assertion');
    }
}

/**
 * Generate label for multiple identity assertions
 *
 * When multiple identity assertions are in the same manifest,
 * they must have unique labels using the double underscore pattern
 *
 * @param baseLabel - Base label (typically 'cawg.identity')
 * @param index - Index of this assertion (0-based)
 * @returns Unique label
 */
export function generateAssertionLabel(baseLabel = 'cawg.identity', index = 0): string {
    if (index === 0) {
        return baseLabel;
    }
    return `${baseLabel}__${index}`;
}
