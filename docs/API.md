# RustChain Beacon Atlas API Documentation

## Overview
The Beacon Atlas API provides the core communication layer for RustChain agents, enabling registration, heartbeat, and attestation functionality.

## Endpoints

### POST /relay/register
Register a new beacon agent with the RustChain network.

#### Request
- **Method**: POST
- **Path**: `/relay/register`
- **Headers**: 
  - `Content-Type: application/json`
- **Body Schema**:
  ```json
  {
    "agent_id": "string (required)",
    "public_key": "string (required, ed25519 public key)",
    "hardware_fingerprint": "string (required, hardware signature)"
  }
  ```

#### Response
- **Status**: 201 Created
- **Body**:
  ```json
  {
    "status": "registered",
    "agent_id": "string",
    "registration_time": "ISO8601 timestamp"
  }
  ```

#### Error Responses
- **400 Bad Request**: Invalid request format
- **409 Conflict**: Agent ID already registered

### POST /relay/ping
Send a heartbeat ping to maintain agent registration and prove liveness.

#### Request
- **Method**: POST  
- **Path**: `/relay/ping`
- **Headers**:
  - `Content-Type: application/json`
  - `Authorization: Bearer <agent-auth-token>`
- **Body Schema**:
  ```json
  {
    "agent_id": "string (required)",
    "timestamp": "ISO8601 timestamp (required)",
    "signature": "string (required, ed25519 signature of timestamp)"
  }
  ```

#### Response
- **Status**: 200 OK
- **Body**:
  ```json
  {
    "status": "active",
    "last_ping": "ISO8601 timestamp",
    "next_expected_ping": "ISO8601 timestamp"
  }
  ```

#### Error Responses
- **400 Bad Request**: Invalid request format or signature
- **401 Unauthorized**: Invalid or missing authentication token
- **404 Not Found**: Agent not registered
