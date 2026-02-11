Run DID resolver with:
```
bun run ./services/did-server/src/server.ts
```

Add a DID document
```
curl -X POST -H "Content-Type: application/json" \
--data '{"id": "did:local:123", "@context":"https://www.w3.org/ns/did/v1","verificationMethod":[]}' \
http://localhost:3000/register
```

Resolve DID document
```
curl http://localhost:3000/resolve/did:local:123
```

Get a list:
```
curl http://localhost:3000/list
```
