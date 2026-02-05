import { X509Certificate } from '@peculiar/x509';

export class TrustList {
    static trustAnchors: X509Certificate[] = [];

    /**
     * Configures global trust anchors used for PKI.js chain validation.
     * Accepts PEM strings (single or multiple concatenated certs), DER bytes, or `X509Certificate` instances.
     */
    public static setTrustAnchors(anchors: (string | Uint8Array | X509Certificate)[]): void {
        const out: X509Certificate[] = [];
        for (const a of anchors) {
            if (typeof a === 'string') {
                for (const der of this.decodeAllPEMCertificates(a)) {
                    try {
                        // Cast to satisfy peculiar/x509 typing expecting ArrayBuffer
                        out.push(new X509Certificate(der as unknown as Uint8Array<ArrayBuffer>));
                    } catch {
                        /* ignore malformed entries */
                    }
                }
            } else if (a instanceof Uint8Array) {
                try {
                    out.push(new X509Certificate(a as unknown as Uint8Array<ArrayBuffer>));
                } catch {
                    /* ignore malformed entries */
                }
            } else if (a instanceof X509Certificate) {
                out.push(a);
            }
        }

        // Replace existing anchors
        TrustList.trustAnchors = out;
    }

    /**
     * Decodes all PEM `CERTIFICATE` sections from a string into DER bytes.
     */
    private static decodeAllPEMCertificates(pem: string): Uint8Array[] {
        const pattern = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
        const out: Uint8Array[] = [];
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(pem)) !== null) {
            const base64 = match[1].replace(/\r?\n|\s/g, '');
            try {
                const buf = Buffer.from(base64, 'base64');
                out.push(new Uint8Array(buf));
            } catch {
                /* ignore invalid blocks */
            }
        }
        return out;
    }
}
