import express, { Request, Response } from 'express';
import { DIDController, DIDDocument, DIDResolutionResult } from './DIDController';



const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// In-memory storage for registered DID documents
// In production, this should be replaced with a persistent database
const didStorage = new Map<string, DIDDocument>();

// Create DID controller instance
const didController = new DIDController({
    cacheTTL: 300000, // 5 minutes
    maxCacheSize: 1000,
    enableCache: true,
});

// Register a custom resolver that checks our local storage first
didController.registerResolver('local', async (did: string): Promise<DIDResolutionResult> => {
    const document = didStorage.get(did);
    
    if (!document) {
        return {
            didDocument: null,
            didResolutionMetadata: {
                error: 'notFound',
                message: `DID not found in registry: ${did}`,
            },
            didDocumentMetadata: {},
        };
    }

    return {
        didDocument: document,
        didResolutionMetadata: {
            retrieved: new Date().toISOString(),
        },
        didDocumentMetadata: {},
    };
});

/**
 * Health check endpoint
 */
app.get('/health', (_req: Request, res: Response) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        service: 'DID Controller',
        version: '1.0.0',
    });
});

/**
 * Register a new DID document
 * 
 * POST /register
 * Body: DIDDocument
 * 
 * Example:
 * {
 *   "@context": ["https://www.w3.org/ns/did/v1"],
 *   "id": "did:local:123456",
 *   "fileHash": "sha256:abcdef...",
 *   "verificationMethod": [...]
 * }
 */
app.post('/register', async (req: Request, res: Response) => {
    try {
        const didDocument: DIDDocument = req.body;

        // Validate required fields
        if (!didDocument['@context']) {
            return res.status(400).json({
                error: 'invalidDocument',
                message: 'Missing required field: @context',
            });
        }

        if (!didDocument.id) {
            return res.status(400).json({
                error: 'invalidDocument',
                message: 'Missing required field: id',
            });
        }

        // Validate DID format
        if (!didController.validateDIDFormat(didDocument.id)) {
            return res.status(400).json({
                error: 'invalidDid',
                message: `Invalid DID format: ${didDocument.id}`,
            });
        }

        // Check if DID already exists
        if (didStorage.has(didDocument.id)) {
            return res.status(409).json({
                error: 'didExists',
                message: `DID already registered: ${didDocument.id}`,
            });
        }

        // Store the DID document
        didStorage.set(didDocument.id, didDocument);

        // Clear cache for this DID to ensure fresh resolution
        didController.clearCache(didDocument.id);

        res.status(201).json({
            success: true,
            did: didDocument.id,
            message: 'DID document registered successfully',
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        console.error('Error registering DID:', error);
        res.status(500).json({
            error: 'internalError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
        });
    }
});

/**
 * Update an existing DID document
 * 
 * PUT /register/:did
 * Body: DIDDocument
 */
app.put('/register/:did', async (req: Request, res: Response) => {
    try {
        const did = decodeURIComponent(req.params.did);
        const didDocument: DIDDocument = req.body;

        // Validate DID format
        if (!didController.validateDIDFormat(did)) {
            return res.status(400).json({
                error: 'invalidDid',
                message: `Invalid DID format: ${did}`,
            });
        }

        // Check if DID exists
        if (!didStorage.has(did)) {
            return res.status(404).json({
                error: 'notFound',
                message: `DID not found: ${did}`,
            });
        }

        // Ensure the ID in the document matches the URL parameter
        if (didDocument.id && didDocument.id !== did) {
            return res.status(400).json({
                error: 'didMismatch',
                message: 'DID in document does not match URL parameter',
            });
        }

        // Update the DID document
        didDocument.id = did; // Ensure ID is set
        didStorage.set(did, didDocument);

        // Clear cache for this DID
        didController.clearCache(did);

        res.json({
            success: true,
            did: didDocument.id,
            message: 'DID document updated successfully',
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        console.error('Error updating DID:', error);
        res.status(500).json({
            error: 'internalError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
        });
    }
});

/**
 * Resolve a DID document
 * 
 * GET /resolve/:did
 * Query params:
 *   - skipCache: boolean (optional) - Skip cache and fetch fresh document
 * 
 * Example: GET /resolve/did:local:123456
 * Example: GET /resolve/did:web:example.com?skipCache=true
 */
app.get('/resolve/:did', async (req: Request, res: Response) => {
    try {
        const did = decodeURIComponent(req.params.did);
        const skipCache = req.query.skipCache === 'true';

        // Validate DID format
        if (!didController.validateDIDFormat(did)) {
            return res.status(400).json({
                error: 'invalidDid',
                message: `Invalid DID format: ${did}`,
            });
        }

        // Check local storage first for did:local
        if (did.startsWith('did:local:')) {
            const document = didStorage.get(did);
            
            if (!document) {
                return res.status(404).json({
                    error: 'notFound',
                    message: `DID not found: ${did}`,
                });
            }

            return res.json({
                didDocument: document,
                didResolutionMetadata: {
                    retrieved: new Date().toISOString(),
                },
                didDocumentMetadata: {},
            });
        }

        // Use the DID controller for other DID methods
        const result = await didController.resolve(did, { skipCache });

        if (!result.didDocument) {
            return res.status(404).json({
                error: result.didResolutionMetadata.error || 'notFound',
                message: result.didResolutionMetadata.message || `Could not resolve DID: ${did}`,
            });
        }

        res.json(result);
    } catch (error) {
        console.error('Error resolving DID:', error);
        res.status(500).json({
            error: 'internalError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
        });
    }
});

/**
 * Delete a DID document
 * 
 * DELETE /register/:did
 */
app.delete('/register/:did', async (req: Request, res: Response) => {
    try {
        const did = decodeURIComponent(req.params.did);

        // Validate DID format
        if (!didController.validateDIDFormat(did)) {
            return res.status(400).json({
                error: 'invalidDid',
                message: `Invalid DID format: ${did}`,
            });
        }

        // Check if DID exists
        if (!didStorage.has(did)) {
            return res.status(404).json({
                error: 'notFound',
                message: `DID not found: ${did}`,
            });
        }

        // Delete the DID document
        didStorage.delete(did);

        // Clear cache for this DID
        didController.clearCache(did);

        res.json({
            success: true,
            did,
            message: 'DID document deleted successfully',
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        console.error('Error deleting DID:', error);
        res.status(500).json({
            error: 'internalError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
        });
    }
});

/**
 * List all registered DIDs
 * 
 * GET /list
 */
app.get('/list', (_req: Request, res: Response) => {
    try {
        const dids = Array.from(didStorage.keys());
        
        res.json({
            count: dids.length,
            dids,
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        console.error('Error listing DIDs:', error);
        res.status(500).json({
            error: 'internalError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
        });
    }
});

/**
 * Get cache statistics
 * 
 * GET /stats
 */
app.get('/stats', (_req: Request, res: Response) => {
    try {
        const cacheStats = didController.getCacheStats();
        
        res.json({
            cache: cacheStats,
            storage: {
                registeredDIDs: didStorage.size,
            },
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        console.error('Error getting stats:', error);
        res.status(500).json({
            error: 'internalError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
        });
    }
});

/**
 * Clear cache
 * 
 * POST /cache/clear
 */
app.post('/cache/clear', (req: Request, res: Response) => {
    try {
        const did = req.body.did as string | undefined;
        
        if (did) {
            didController.clearCache(did);
            res.json({
                success: true,
                message: `Cache cleared for DID: ${did}`,
            });
        } else {
            didController.clearCache();
            res.json({
                success: true,
                message: 'All cache cleared',
            });
        }
    } catch (error) {
        console.error('Error clearing cache:', error);
        res.status(500).json({
            error: 'internalError',
            message: error instanceof Error ? error.message : 'Unknown error occurred',
        });
    }
});

// Start server
app.listen(port, () => {
    console.log(`DID Controller Server running on port ${port}`);
    console.log(`Health check: http://localhost:${port}/health`);
    console.log(`Register DID: POST http://localhost:${port}/register`);
    console.log(`Resolve DID: GET http://localhost:${port}/resolve/:did`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received: closing HTTP server');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT signal received: closing HTTP server');
    process.exit(0);
});
