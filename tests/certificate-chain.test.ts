import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {
    AuthorityKeyIdentifierExtension,
    BasicConstraintsExtension,
    ExtendedKeyUsage,
    ExtendedKeyUsageExtension,
    KeyUsageFlags,
    KeyUsagesExtension,
    SubjectKeyIdentifierExtension,
    X509Certificate,
    X509CertificateCreateParams,
    X509CertificateCreateSelfSignedParams,
    X509CertificateGenerator,
} from '@peculiar/x509';
import { beforeAll, describe, it } from 'bun:test';
import { JPEG } from '../src/asset';
import { CoseAlgorithmIdentifier, LocalSigner, TrustList } from '../src/cose';
import { SuperBox } from '../src/jumbf';
import { DataHashAssertion, ManifestStore, ValidationResult } from '../src/manifest';
import { LocalTimestampProvider } from '../src/rfc3161';
import {
    getExpectedValidationStatusEntries,
    getExpectedValidationStatusEntriesInvalid,
    getExpectedValidationStatusEntriesUntrusted,
} from './utils/testCertificates';

// location of the image to sign
const sourceFile = 'tests/fixtures/trustnxt-icon.jpg';
// location of the signed image
const targetFile = 'tests/fixtures/trustnxt-icon-certificate-chain-signed.jpg';

async function getValidationResult(
    signer: LocalSigner,
    timestampProvider: LocalTimestampProvider,
): Promise<[ValidationResult, string]> {
    // load the file into a buffer
    const buf = await fs.readFile(sourceFile);
    assert.ok(buf);

    // ensure it's a JPEG
    assert.ok(await JPEG.canRead(buf));

    // construct the asset
    const asset = await JPEG.create(buf);

    // create a new manifest store and append a new manifest
    const manifestStore = new ManifestStore();
    const manifest = manifestStore.createManifest({
        assetFormat: 'image/jpeg',
        instanceID: 'xyzxyz2',
        defaultHashAlgorithm: 'SHA-256',
        signer,
    });

    // create a data hash assertion
    const dataHashAssertion = DataHashAssertion.create('SHA-512');
    manifest.addAssertion(dataHashAssertion);

    // make space in the asset
    await asset.ensureManifestSpace(manifestStore.measureSize());

    // update the hard binding
    await dataHashAssertion.updateWithAsset(asset);

    // create the signature
    await manifest.sign(signer, timestampProvider);

    // write the JUMBF box to the asset
    await asset.writeManifestJUMBF(manifestStore.getBytes());

    // write the asset to the target file
    await fs.writeFile(targetFile, await asset.getDataRange());

    // load the file into a buffer
    const targetBuf = await fs.readFile(targetFile);
    assert.ok(targetBuf);

    // ensure it's a JPEG
    assert.ok(await JPEG.canRead(targetBuf));

    // construct the asset
    const targetAsset = await JPEG.create(targetBuf);

    // extract the C2PA manifest store in binary JUMBF format
    const jumbf = await targetAsset.getManifestJUMBF();
    assert.ok(jumbf, 'no JUMBF found');

    // deserialize the JUMBF box structure
    const superBox = SuperBox.fromBuffer(jumbf);

    // construct the manifest store from the JUMBF box
    const targetManifestStore = ManifestStore.read(superBox);

    // get active manifest
    const targetManifest = targetManifestStore.getActiveManifest();
    assert.ok(targetManifest, 'No active manifest found');
    assert.ok(targetManifest.signature, 'No signature found in manifest');

    // validate the asset against the store
    const validationResult = await targetManifestStore.validate(targetAsset);

    // delete test file, ignore the case it doesn't exist
    await fs.unlink(targetFile).catch(() => undefined);

    assert.ok(targetManifest.label, 'No manifest label');
    return [validationResult, targetManifest.label];
}

async function toPkcs8Bytes(key: CryptoKey): Promise<Uint8Array> {
    const der = await crypto.subtle.exportKey('pkcs8', key); // ArrayBuffer (DER)
    return new Uint8Array(der);
}

async function createRootCertificate(
    partial?: Partial<X509CertificateCreateSelfSignedParams>,
): Promise<[CryptoKeyPair, X509Certificate]> {
    const rootKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const rootCert = await X509CertificateGenerator.createSelfSigned(
        {
            serialNumber: '01',
            name: `C=NL, ST=Zuid-Holland, O=Dawn Technology, OU=Development, CN=Root`,
            keys: rootKeys,
            signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
            extensions: [
                new BasicConstraintsExtension(true, 3, true),
                new KeyUsagesExtension(
                    KeyUsageFlags.digitalSignature + KeyUsageFlags.keyCertSign + KeyUsageFlags.cRLSign,
                    true,
                ),
                await SubjectKeyIdentifierExtension.create(rootKeys.publicKey, false),
                await AuthorityKeyIdentifierExtension.create(rootKeys.publicKey, false),
            ],
            ...partial,
        },
        crypto,
    );

    return [rootKeys, rootCert];
}
async function createIntermediateCertificate(
    rootCert: X509Certificate,
    rootKeys: CryptoKeyPair,
    partial?: Partial<X509CertificateCreateParams>,
): Promise<[CryptoKeyPair, X509Certificate]> {
    const intermediateKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        'sign',
        'verify',
    ]);
    const intermediateCert = await X509CertificateGenerator.create(
        {
            serialNumber: '02',
            subject: `C=NL, ST=Zuid-Holland, O=Dawn Technology, OU=Development, CN=Intermediate`,
            issuer: rootCert.subject,
            signingKey: rootKeys.privateKey,
            publicKey: intermediateKeys.publicKey,
            signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
            extensions: [
                new BasicConstraintsExtension(false, 2, true),
                new ExtendedKeyUsageExtension([ExtendedKeyUsage.emailProtection], true),
                new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
                await SubjectKeyIdentifierExtension.create(intermediateKeys.publicKey, false),
                await AuthorityKeyIdentifierExtension.create(rootKeys.publicKey, false),
            ],
            ...partial,
        },
        crypto,
    );

    return [intermediateKeys, intermediateCert];
}

async function createLeafCertificate(
    intermediateCert: X509Certificate,
    intermediateKeys: CryptoKeyPair,
    partial?: Partial<X509CertificateCreateParams>,
): Promise<[CryptoKeyPair, X509Certificate]> {
    const leafKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const leafCert = await X509CertificateGenerator.create(
        {
            serialNumber: '03',
            subject: `C=NL, ST=Zuid-Holland, O=Dawn Technology, OU=Development, CN=Leaf`,
            issuer: intermediateCert.subject,
            signingKey: intermediateKeys.privateKey,
            publicKey: leafKeys.publicKey,
            signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
            extensions: [
                new BasicConstraintsExtension(false, 1, true),
                new ExtendedKeyUsageExtension([ExtendedKeyUsage.emailProtection], true),
                new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
                await SubjectKeyIdentifierExtension.create(leafKeys.publicKey, false),
                await AuthorityKeyIdentifierExtension.create(intermediateKeys.publicKey, false),
            ],
            ...partial,
        },
        crypto,
    );
    return [leafKeys, leafCert];
}
describe('Certificate Chain Validation', () => {
    // const year = new Date().getFullYear();
    let rootCert: X509Certificate;
    let rootKeys: CryptoKeyPair;
    let intermediateCert: X509Certificate;
    let intermediateKeys: CryptoKeyPair;
    let leafCert: X509Certificate;
    let leafKeys: CryptoKeyPair;
    let timestampProvider: LocalTimestampProvider;
    let signer: LocalSigner;

    beforeAll(async () => {
        // Generate test certificates
        [rootKeys, rootCert] = await createRootCertificate();
        [intermediateKeys, intermediateCert] = await createIntermediateCertificate(rootCert, rootKeys);
        [leafKeys, leafCert] = await createLeafCertificate(intermediateCert, intermediateKeys);

        // Create timestamp provider
        timestampProvider = new LocalTimestampProvider(leafCert, await toPkcs8Bytes(leafKeys.privateKey), [
            intermediateCert,
        ]);
        // Create a signer
        signer = new LocalSigner(await toPkcs8Bytes(leafKeys.privateKey), CoseAlgorithmIdentifier.ES256, leafCert, [
            intermediateCert,
        ]);

        TrustList.setTrustAnchors([rootCert]);
    });

    describe('1. Basic Certificate Chain Structure', () => {
        it('should accept valid 3-level chain (root → intermediate → leaf)', async () => {
            // Test chain building: leaf → intermediate → root
            const [validationResult, label] = await getValidationResult(signer, timestampProvider);

            // check individual codes
            assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntries(label));

            // // check overall validity
            assert.ok(validationResult.isValid, 'Validation result invalid');
        });

        it('should accept valid 2-level chain (root → leaf)', async () => {
            const [directLeafKeys, directLeafCert] = await createLeafCertificate(rootCert, rootKeys); // Create a leaf certificate directly signed by the root
            // Create timestamp provider
            const otherTimestampProvider = new LocalTimestampProvider(
                directLeafCert,
                await toPkcs8Bytes(directLeafKeys.privateKey),
                [rootCert],
            );
            // Create a signer
            const otherSigner = new LocalSigner(
                await toPkcs8Bytes(directLeafKeys.privateKey),
                CoseAlgorithmIdentifier.ES256,
                directLeafCert,
                [rootCert],
            );

            const [validationResult, label] = await getValidationResult(otherSigner, otherTimestampProvider);

            // check individual codes
            assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntries(label));

            // // check overall validity
            assert.ok(validationResult.isValid, 'Validation result invalid');
        });

        it('should accept self-signed root certificate', async () => {
            // Create timestamp provider
            const otherTimestampProvider = new LocalTimestampProvider(
                rootCert,
                await toPkcs8Bytes(rootKeys.privateKey),
            );
            // Create a signer
            const otherSigner = new LocalSigner(
                await toPkcs8Bytes(rootKeys.privateKey),
                CoseAlgorithmIdentifier.ES256,
                rootCert,
            );

            const [validationResult, label] = await getValidationResult(otherSigner, otherTimestampProvider);

            // check individual codes
            assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntriesInvalid(label));

            // // check overall validity
            assert.ok(!validationResult.isValid, 'Validation result should be invalid');
        });

        it('should detect when intermediate certificate is missing', async () => {
            // Create timestamp provider
            const otherTimestampProvider = new LocalTimestampProvider(
                rootCert,
                await toPkcs8Bytes(rootKeys.privateKey),
                [intermediateCert],
            );
            // Create a signer
            const otherSigner = new LocalSigner(
                await toPkcs8Bytes(rootKeys.privateKey),
                CoseAlgorithmIdentifier.ES256,
                rootCert,
            );

            const [validationResult, label] = await getValidationResult(otherSigner, otherTimestampProvider);

            // check individual codes
            assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntriesInvalid(label));

            // // check overall validity
            assert.ok(!validationResult.isValid, 'Validation result should be invalid');
        });
    });

    describe('2. Certificate Signature Verification', () => {
        it('should detect invalid signature', async () => {
            const wrongRootKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
                'sign',
                'verify',
            ]);
            const wrongIntermediateCert = await X509CertificateGenerator.create(
                {
                    serialNumber: '02',
                    subject: `C=NL, ST=Zuid-Holland, O=Dawn Technology, OU=Development, CN=Intermediate`,
                    issuer: rootCert.subject,
                    signingKey: wrongRootKeys.privateKey,
                    publicKey: intermediateKeys.publicKey,
                    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
                    extensions: [
                        new BasicConstraintsExtension(false, 2, true),
                        new ExtendedKeyUsageExtension([ExtendedKeyUsage.emailProtection], true),
                        new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
                        await SubjectKeyIdentifierExtension.create(intermediateKeys.publicKey, false),
                        await AuthorityKeyIdentifierExtension.create(wrongRootKeys.publicKey, false),
                    ],
                },
                crypto,
            );

            // Create timestamp provider
            const otherTimestampProvider = new LocalTimestampProvider(
                leafCert,
                await toPkcs8Bytes(leafKeys.privateKey),
                [wrongIntermediateCert],
            );
            // Create a signer
            const otherSigner = new LocalSigner(
                await toPkcs8Bytes(leafKeys.privateKey),
                CoseAlgorithmIdentifier.ES256,
                leafCert,
                [wrongIntermediateCert],
            );

            const [validationResult, label] = await getValidationResult(otherSigner, otherTimestampProvider);

            // check individual codes
            assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntriesUntrusted(label));

            // // check overall validity
            assert.ok(!validationResult.isValid, 'Validation result should be invalid');
        });

        // it('should deal with irrelevant certificates in the chain', async () => {
        //     const anyKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
        //         'sign',
        //         'verify',
        //     ]);
        //     const anyCert = await X509CertificateGenerator.create(
        //         {
        //             serialNumber: '04',
        //             subject: `C=NL, ST=Zuid-Holland, O=Dawn Technology, OU=Development, CN=Irrelevant`,
        //             issuer: rootCert.subject,
        //             signingKey: anyKeys.privateKey,
        //             publicKey: anyKeys.publicKey,
        //             signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        //         },
        //         crypto,
        //     );

        //     // Create timestamp provider
        //     const otherTimestampProvider = new LocalTimestampProvider(
        //         leafCert,
        //         await toPkcs8Bytes(leafKeys.privateKey),
        //         [intermediateCert, anyCert],
        //     );
        //     // Create a signer
        //     const otherSigner = new LocalSigner(
        //         await toPkcs8Bytes(leafKeys.privateKey),
        //         CoseAlgorithmIdentifier.ES256,
        //         leafCert,
        //         [intermediateCert, anyCert],
        //     );

        //     const [validationResult, label] = await getValidationResult(otherSigner, otherTimestampProvider);

        //     // check individual codes
        //     assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntries(label));

        //     // // check overall validity
        //     assert.ok(validationResult.isValid, 'Validation result should be valid');
        // });

        // it('should support different signature algorithms', async () => {
        //     // Test ECDSA
        //     expect(leafCert.signatureAlgorithm.name).toBe('ECDSA');

        //     // Test RSA
        //     const rsaKeys = await crypto.subtle.generateKey(
        //         {
        //             name: 'RSASSA-PKCS1-v1_5',
        //             hash: 'SHA-256',
        //             modulusLength: 2048,
        //             publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        //         } as RsaHashedKeyGenParams,
        //         true,
        //         ['sign', 'verify'],
        //     );
        //     const rsaCert = await X509CertificateGenerator.createSelfSigned(
        //         {
        //             serialNumber: '10',
        //             name: 'CN=RSA Test',
        //             keys: rsaKeys,
        //             signingAlgorithm: {
        //                 name: 'RSASSA-PKCS1-v1_5',
        //                 hash: 'SHA-256',
        //             },
        //         },
        //         crypto,
        //     );

        //     // Create timestamp provider
        //     const otherTimestampProvider = new LocalTimestampProvider(rsaCert, await toPkcs8Bytes(rsaKeys.privateKey), [
        //         intermediateCert,
        //     ]);
        //     // Create a signer
        //     const otherSigner = new LocalSigner(
        //         await toPkcs8Bytes(rsaKeys.privateKey),
        //         CoseAlgorithmIdentifier.ES256,
        //         rsaCert,
        //         [intermediateCert],
        //     );

        //     const [validationResult, label] = await getValidationResult(otherSigner, otherTimestampProvider);

        //     // check individual codes
        //     assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntries(label));

        //     // // check overall validity
        //     assert.ok(!validationResult.isValid, 'Validation result should be invalid');
        // });
    });

    describe('3. Certificate Validity Period', () => {
        it('should accept certificate within validity period', async () => {
            // Generate test certificates
            const [otherRootKeys, otherRootCert] = await createRootCertificate({ notBefore: new Date() });
            const [otherIntermediateKeys, otherIntermediateCert] = await createIntermediateCertificate(
                otherRootCert,
                otherRootKeys,
                { notBefore: new Date() },
            );
            const [otherLeafKeys, otherLeafCert] = await createLeafCertificate(
                otherIntermediateCert,
                otherIntermediateKeys,
                { notBefore: new Date() },
            );

            // Create timestamp provider
            const otherTimestampProvider = new LocalTimestampProvider(
                otherLeafCert,
                await toPkcs8Bytes(otherLeafKeys.privateKey),
                [otherIntermediateCert],
            );
            // Create a signer
            const otherSigner = new LocalSigner(
                await toPkcs8Bytes(otherLeafKeys.privateKey),
                CoseAlgorithmIdentifier.ES256,
                otherLeafCert,
                [otherIntermediateCert],
            );

            TrustList.setTrustAnchors([otherRootCert]);

            const [validationResult, label] = await getValidationResult(otherSigner, otherTimestampProvider);

            // check individual codes
            assert.deepEqual(validationResult.statusEntries, getExpectedValidationStatusEntries(label));

            // // check overall validity
            assert.ok(validationResult.isValid, 'Validation result should be valid');
        });

        it('should detect expired certificate', async () => {
            // TODO
        });

        it('should detect not-yet-valid certificate', async () => {
            // TODO
        });
    });

    // describe('4. Key Usage Extensions', () => {
    //     it('should have digitalSignature key usage for leaf certificates', () => {
    //         const keyUsage = leafCert.getExtension('2.5.29.15'); // KeyUsage OID
    //         expect(keyUsage).toBeDefined();
    //     });

    //     it('should only allow keyCertSign for CA certificates', () => {
    //         // Root and intermediate are CAs
    //         expect(rootCert.getExtension('2.5.29.19')).toBeDefined(); // Basic Constraints
    //         expect(intermediateCert.getExtension('2.5.29.19')).toBeDefined();
    //     });

    //     it('should have critical flag on KeyUsage extension', () => {
    //         const keyUsage = leafCert.getExtension('2.5.29.15');
    //         expect(keyUsage?.critical).toBe(true);
    //     });
    // });

    // describe('5. Extended Key Usage (EKU)', () => {
    //     it('should accept EmailProtection EKU', () => {
    //         const eku = leafCert.getExtension('2.5.29.37'); // EKU OID
    //         expect(eku).toBeDefined();
    //     });

    //     it('should only allow TimeStamping EKU without other EKUs', async () => {
    //         const tsKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    //             'sign',
    //             'verify',
    //         ]);
    //         const tsCert = await X509CertificateGenerator.createSelfSigned(
    //             {
    //                 serialNumber: '30',
    //                 name: 'CN=Timestamp',
    //                 notBefore: new Date('2024-01-01'),
    //                 notAfter: new Date('2026-01-01'),
    //                 keys: tsKeys,
    //                 signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    //                 extensions: [
    //                     new ExtendedKeyUsageExtension([ExtendedKeyUsage.timeStamping], false), // timeStamping only
    //                 ],
    //             },
    //             crypto,
    //         );
    //         const eku = tsCert.getExtension('2.5.29.37');
    //         expect(eku).toBeDefined();
    //     });
    // });

    // describe('6. Basic Constraints', () => {
    //     it('should have CA flag in intermediate certificates', () => {
    //         const bc = intermediateCert.getExtension('2.5.29.19');
    //         expect(bc).toBeDefined();
    //         expect(bc?.critical).toBe(true);
    //     });

    //     it('should respect pathLength constraint', () => {
    //         // Intermediate has pathLength: 0, so cannot have sub-CAs
    //         const bc = intermediateCert.getExtension('2.5.29.19');
    //         expect(bc).toBeDefined();
    //     });
    // });

    // describe('8. Certificate Algorithms', () => {
    //     it('should support ECDSA with SHA-256', () => {
    //         expect(leafCert.signatureAlgorithm.name).toBe('ECDSA');
    //     });

    //     it('should support RSA with at least 2048 bits', async () => {
    //         const rsaKeys = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5' }, true, ['sign', 'verify']);
    //         const rsaCert = await X509CertificateGenerator.createSelfSigned(
    //             {
    //                 serialNumber: '40',
    //                 name: 'CN=RSA 2048',
    //                 notBefore: new Date('2024-01-01'),
    //                 notAfter: new Date('2026-01-01'),
    //                 keys: rsaKeys as CryptoKeyPair,
    //                 signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    //             },
    //             crypto,
    //         );
    //         expect(rsaCert.publicKey.algorithm.name).toBe('RSASSA-PKCS1-v1_5');
    //     });
    // });

    // describe('10. Error Handling', () => {
    //     it('should handle malformed certificate data', () => {
    //         expect(() => {
    //             new X509Certificate(new Uint8Array([1, 2, 3, 4]));
    //         }).toThrow();
    //     });

    //     it('should handle empty certificate data', () => {
    //         expect(() => {
    //             new X509Certificate(new Uint8Array(0));
    //         }).toThrow();
    //     });
    // });

    // describe('11. Loop Detection', () => {
    //     it('should detect circular certificate references', () => {
    //         // If a certificate chain contains a loop (A → B → C → B)
    //         // This should be detected
    //         const subjects = new Set<string>();
    //         subjects.add(leafCert.subject);
    //         subjects.add(intermediateCert.subject);
    //         subjects.add(rootCert.subject);

    //         // No duplicates = no loop
    //         expect(subjects.size).toBe(3);
    //     });
    // });

    // describe('12. Subject/Issuer Matching', () => {
    //     it('should match subject of issuer with issuer of certificate', () => {
    //         expect(leafCert.issuer).toBe(intermediateCert.subject);
    //         expect(intermediateCert.issuer).toBe(rootCert.subject);
    //     });

    //     it('should recognize self-signed certificates', () => {
    //         expect(rootCert.subject).toBe(rootCert.issuer);
    //         expect(leafCert.subject).not.toBe(leafCert.issuer);
    //     });
    // });
});
