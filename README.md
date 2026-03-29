# RustChain

Proof-of-Antiquity blockchain — vintage PowerPC hardware earns 2.5x mining rewards. Hardware fingerprinting, Solana bridge (wRTC), AI agent economy.

## Quick Start

### Mining
```bash
# Clone the miner
git clone https://github.com/Scottcjn/Rustchain.git

# Run it (replace YOUR_WALLET_ID with your chosen name)
python3 rustchain_miner.py --wallet YOUR_WALLET_ID --node https://50.28.86.131
```

### Check Your Balance
```bash
curl -sk "https://50.28.86.131/wallet/balance?miner_id=YOUR_WALLET_ID"
```

## Beacon Atlas Endpoints

The Beacon Atlas provides a set of HTTP endpoints for agent communication and attestation:

#### `/relay/register`
Register a new beacon agent with the network.

**Request**: `POST /relay/register`
- **Headers**: `Content-Type: application/json`
- **Body**: 
  ```json
  {
    "agent_id": "unique-agent-identifier",
    "public_key": "ed25519-public-key",
    "hardware_fingerprint": "hardware-signature"
  }
  ```

**Response**: `201 Created`
- **Body**: 
  ```json
  {
    "status": "registered",
    "agent_id": "unique-agent-identifier",
    "registration_time": "2026-02-26T10:00:00Z"
  }
  ```

#### `/relay/ping`
Send a heartbeat ping to maintain agent registration.

**Request**: `POST /relay/ping`
- **Headers**: `Content-Type: application/json`, `Authorization: Bearer <agent-token>`
- **Body**: 
  ```json
  {
    "agent_id": "unique-agent-identifier",
    "timestamp": "2026-02-26T10:00:00Z",
    "signature": "ed25519-signature"
  }
  ```

**Response**: `200 OK`
- **Body**: 
  ```json
  {
    "status": "active",
    "last_ping": "2026-02-26T10:00:00Z",
    "next_expected_ping": "2026-02-26T10:05:00Z"
  }
  ```

## Network Info

- **Node (Primary)**: [https://50.28.86.131](https://50.28.86.131)
- **Health Check**: [https://50.28.86.131/health](https://50.28.86.131/health)
- **Block Explorer**: [https://50.28.86.131/explorer](https://50.28.86.131/explorer)

## Contributing

- Fork this repo
- Work on a bounty
- Submit a PR referencing the issue number
- Maintainer reviews and pays out in RTC

## License

Apache 2.0
