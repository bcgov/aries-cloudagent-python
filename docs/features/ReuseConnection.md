# Reusing Connections Between Agents

Leverage ACA‑Py's Out‑of‑Band (OOB) protocol to reuse existing connections instead of creating new ones for every interaction.

---

## Quick Start

*For developers who want code now*

### 1. Generate a Reusable Invitation

Use the following API call to create an invitation that supports connection reuse. Note that the invitation must include a resolvable DID (e.g., `did:peer:2`) in its `services` field. This is achieved by setting the `use_did_method` parameter.

```bash
curl -X POST 'http://your-agent-admin:8031/out-of-band/create-invitation?auto_accept=true&multi_use=true' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer YOUR_API_KEY' \
  -d '{
    "handshake_protocols": ["https://didcomm.org/didexchange/1.1"],
    "protocol_version": "1.1",
    "use_did_method": "did:peer:2"
  }'
```

### 2. Verify the Response

Ensure that the response contains a `services` array with a resolvable DID:

```json
{
  "state": "initial",
  "trace": false,
  "invi_msg_id": "ffaf017e-3980-45b7-ad43-a90a609d6eaf",
  "oob_id": "ed7cc3f6-62cd-4b53-9285-534c198a8476",
  "invitation": {
    "@type": "https://didcomm.org/out-of-band/1.1/invitation",
    "@id": "ffaf017e-3980-45b7-ad43-a90a609d6eaf",
    "label": "First invitation to Barry",
    "imageUrl": "https://example-image.com",
    "handshake_protocols": [
      "https://didcomm.org/didexchange/1.1"
    ],
    "services": [
      "did:peer:2.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7"
    ]
  },
  "invitation_url": "https://example-admin.com?oob=example-1-invite-encoded-url"
}
```

### 3. Reuse the Connection

When an invitee scans subsequent invitations that contain the **same DID**, ACA‑Py automatically sends a `reuse` message instead of creating a new connection.

---

## Key Concepts

### What Enables Connection Reuse?

1. **Resolvable DID**  
   - The invitation’s `services` array **must** include a resolvable DID (e.g., `did:peer:2` or `did:peer:4`), as specified by the `use_did_method` parameter.
   - *Do not use inline or non‑resolvable DIDs (e.g., `did:key`).*

2. **Consistent DID Across Invitations**  
   - The inviter (e.g., the issuer) must reuse the same resolvable DID in subsequent invitations where reuse is desired. This consistency is enforced by setting `use_did_method` to `did:peer:2` (or `did:peer:4`) in the API call.

3. **Protocol Version**  
   - Use `didexchange/1.1` (avoid the legacy `1.0`).

#### Critical API Parameters

| Parameter            | Description                                                      |
|----------------------|------------------------------------------------------------------|
| `use_did_method`     | Set to `did:peer:2` or `did:peer:4` (required for reuse).         |
| `multi_use`          | Optional but recommended for enabling multi‑use invitations.     |
| `handshake_protocols`| Must include `https://didcomm.org/didexchange/1.1`.              |

---

## Handling Reuse Events

When a connection is reused, ACA-Py automatically emits an event notification. This event contains the `connection_id` of the reused connection, allowing applications to track reuse activity programmatically.

### Example Event Notification

```json
{
  "thread_id": "096cf986-9211-450c-9cbb-a6d701c4d9ca",
  "connection_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "comment": "Connection 28818825-98a3-44c7-b1cc-d429c1583a1d is being reused for invitation 6f6af313-3735-4ac1-b972-aafebd3731bc"
}
```

### Listening for Reuse Events

Applications can subscribe to these events via the WebSocket or webhooks event stream provided by ACA-Py. To listen for reuse events:

1. Connect to the ACA-Py WebSocket server or setup a webhook endpoint.
2. Filter events with `type=connection_reuse`.
3. Handle the event in your application logic.

---

## Troubleshooting

| **Symptom**                                | **Likely Cause**                           | **Solution**                                                                          |
|--------------------------------------------|--------------------------------------------|---------------------------------------------------------------------------------------|
| New connection created instead of reused   | Invitation uses a non‑resolvable DID, `use_did_method` not set        | Set `use_did_method=did:peer:2` (or `did:peer:4`) in the `/out-of-band/create-invitation` call. |
| `reuse` message not sent                    | Invitee agent doesn’t support OOB v1.1       | Ensure both agents are using `didexchange/1.1`.                                         |
| DID resolution failed                       | The resolver does not support the chosen DID | Configure a DID resolver that supports the selected peer DID method.                    |

---

## Demo vs. Production

| **Scenario** | **Approach**                                                                 |
|--------------|------------------------------------------------------------------------------|
| **Demo**     | Use CLI flags such as `--reuse-connections`.                                 |
| **Production**| Rely on API parameters (`use_did_method`, `multi_use`) for reuse events. |

---

**Contributor Note:**  
Tested with BC Wallet & Hologram apps. Reuse functionality has been confirmed to work with `did:peer:2` (see [Issue #3532](https://github.com/hyperledger/aries-cloudagent-python/issues/3532)).

For more information on Qualified DIDs (e.g., `did:peer:2`, `did:peer:4`), visit the [Qualified DIDs Documentation](https://aca-py.org/latest/features/QualifiedDIDs/).

