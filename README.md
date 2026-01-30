# Mesh MQTT Server

A Meshtastic-aware MQTT server designed for the Western PA Mesh network. This server provides enhanced MQTT capabilities with Meshtastic protocol support, user authentication, and a web interface for mesh network management.

## Features

- **Meshtastic Protocol Support**: Native support for Meshtastic mesh networking protocol
- **MQTT Broker**: Built-in MQTT broker with custom hooks for mesh packet processing
- **User Authentication**: OAuth2 integration (Discord) with session management
- **Web Interface**: Dashboard for viewing nodes and network status
- **PostgreSQL Backend**: Persistent storage for nodes, users, and OAuth tokens
- **Packet Encryption**: AES-CTR (PSK) and AES-CCM with Curve25519 (PKI) encryption
- **Node Management**: Automatic node detection, tracking, and database persistence
- **Gateway Support**: Advanced gateway topic handling with permission-based access control
- **Downlink Verification**: Validates bidirectional communication with mesh nodes

## Requirements

- Go 1.24.3 or later
- PostgreSQL database
- Discord OAuth application (for authentication)

## Configuration

Create a `config.yml` file with the following structure:

```yaml
ListenAddr: ":8080"
SessionSecret: "your-session-secret-here"
BaseURL: "https://your-domain.com"

OAuth:
  Discord:
    ClientID: "your-discord-client-id"
    ClientSecret: "your-discord-client-secret"
    Endpoint:
      AuthURL: "https://discord.com/api/oauth2/authorize"
      TokenURL: "https://discord.com/api/oauth2/token"
    RedirectURL: "https://your-domain.com/auth/discord/callback"
    Scopes:
      - identify

MeshSettings:
  MqttRoot: "msh/US/2/e/"
  Channels:
    - Name: "LongFast"
      Key: "AQ=="  # Base64 encoded channel key
      Export: true  # Include this channel in exported configs
  VerificationChannels:  # Channels to try for downlink verification (in order)
    - "LongFast"
  SelfNode:
    NodeID: "!12345678"
    LongName: "Western PA Mesh Server"
    ShortName: "WPAMesh"

# Optional: Forward packets to external MQTT servers
Forwarding:
  Enabled: false
  Targets:
    - Name: "meshtastic-public"
      Address: "mqtt.meshtastic.org:1883"
      Username: "meshdev"
      Password: "large4cats"
      UseTLS: false
      Topics:
        - "msh/#"
      TopicRewrites:
        "msh/US/2/e": "msh/US/PA/WPAmesh/2/e"

Database:
  User: "postgres"
  Password: "your-db-password"
  Host: "localhost:5432"
  DB: "mesh_mqtt"
```

## Installation

1. Clone the repository:
```bash
git clone git@github.com:kabili207/mesh-mqtt-server.git
cd mesh-mqtt-server
```

2. Install dependencies:
```bash
go mod download
```

3. Set up your PostgreSQL database and update the configuration file

4. Build the server:
```bash
go build -o mesh-mqtt-server ./cmd/server
```

## Usage

Run the server with the default config file:
```bash
./mesh-mqtt-server
```

Or specify a custom config file:
```bash
./mesh-mqtt-server -c /path/to/config.yml
```

The server will:
- Start the MQTT broker on port 1883
- Start the web interface on the configured `ListenAddr`
- Automatically run database migrations
- Begin processing mesh packets

## MQTT Connection

Connect to the MQTT broker at `localhost:1883` (or your configured address). The server supports standard MQTT clients and includes Meshtastic-specific packet handling.

## Web Interface

Access the web interface at your configured `BaseURL` to:
- View all mesh nodes
- See your registered nodes
- Monitor network activity

## Advanced Features

### Gateway Topic Support

The server implements intelligent gateway topic handling designed to maintain a healthy, LoRa-first mesh network while still providing MQTT connectivity for isolated users.

**Why Restrict Gateway Access?**

Unlike the public Meshtastic MQTT network (which uses a zero-hop strategy to prevent MQTT from overwhelming the mesh), the Western PA Mesh's challenging, hilly geography requires a different approach:

- **LoRa-First Priority**: The mesh should primarily operate over LoRa radio, not depend on internet connectivity
- **Hop Preservation**: Packets must traverse the mesh without hop count modification to reach isolated users across difficult terrain
- **Routing Stability**: Unrestricted MQTT access can create routing issues, especially when uplink and downlink paths aren't symmetrical
- **Strategic Gateway Placement**: By carefully limiting which nodes can act as gateways, we bridge larger city/county regions to isolated nodes without creating a mesh dependent on internet backhaul

**Gateway vs Non-Gateway Nodes:**

- **Gateway Nodes**: Authorized to publish packets that will be relayed over LoRa with preserved hop counts. These are strategically placed to connect regions while maintaining mesh health.
- **Non-Gateway Nodes**: Can still connect via MQTT for monitoring and network mapping, but their messages won't be relayed to LoRa. This helps visualize the full network without creating routing issues.

**Topic Format:**
```
msh/region/Gateway/2/e/channel/nodeID  # Gateway-enabled nodes
msh/region/2/e/channel/nodeID          # Standard topic (auto-rewritten for non-gateway)
```

**Permission System:**
- Gateway access is permission-based and stored in the database
- Users without gateway permission have their topics automatically rewritten to standard format
- The server validates both user permissions and node roles before allowing gateway features
- Prevents asymmetric routing scenarios that can destabilize mesh connectivity

### Downlink Verification

The server includes a downlink verification system to ensure bidirectional communication with mesh nodes, which is critical for gateway-enabled nodes:

**How It Works:**
1. When a node subscribes to a gateway topic, the server sends a NodeInfo request packet
2. The server tries channels from `VerificationChannels` in order, waiting 60 seconds per channel
3. When the node responds, its primary channel is recorded and used for future verifications
4. Verification is valid for 3 days; re-verification triggers automatically after 1 day

**Multi-Channel Verification:**

Nodes may be configured for different channels (LongFast, MediumSlow, etc.). The server handles this by:
- Trying each channel in the `VerificationChannels` list sequentially
- Waiting 60 seconds per channel before trying the next
- Recording whichever channel successfully receives a response as the node's "primary channel"
- Using the primary channel directly for future re-verifications

**Timing:**
- Per-channel timeout: 60 seconds
- Overall verification window: 15 minutes
- Verification validity: 3 days
- Re-verification threshold: 1 day (triggers early renewal)
- Periodic check interval: 1 hour

**Why This Matters:**
- Confirms the node can receive downlink messages (not just send uplink)
- Validates that gateway-enabled nodes have symmetric routing before allowing them to inject packets into the LoRa mesh
- Helps identify nodes with asymmetric connectivity that could cause routing issues
- Prevents misconfigured clients from disrupting mesh operations

**Configuration:**
Verification happens automatically for nodes using gateway topics. Configure `VerificationChannels` in the config to specify which channels to try and in what order. The server sends packets as its configured `SelfNode` identity with the CLIENT_MUTE role to avoid interfering with normal mesh operations.

### MQTT Forwarding

The server can forward packets to external MQTT servers, useful for bridging to the public Meshtastic network or other infrastructure:

**Features:**
- Forward to multiple targets simultaneously
- Topic pattern filtering (e.g., only forward `msh/#`)
- Topic rewriting rules to transform topics before forwarding
- TLS support for secure connections
- Automatic reconnection on failure

**Configuration:**
```yaml
Forwarding:
  Enabled: true
  Targets:
    - Name: "meshtastic-public"
      Address: "mqtt.meshtastic.org:1883"
      Username: "meshdev"
      Password: "large4cats"
      UseTLS: false
      Topics:
        - "msh/#"
      TopicRewrites:
        "msh/US/2/e": "msh/US/PA/WPAmesh/2/e"
```

**Use Cases:**
- Bridge local mesh traffic to the public Meshtastic MQTT server
- Rewrite topics to place your network under a regional hierarchy
- Forward to multiple servers for redundancy or different purposes

### Access Control

The server implements role-based access control (ACL) for all MQTT operations:

- **Superusers**: Full access to all topics including `$SYS` system topics
- **Gateway-Enabled Mesh Devices**: Can publish packets that will be relayed over LoRa (requires permission + verification)
- **Non-Gateway Mesh Devices**: Can publish for monitoring/mapping purposes; messages not relayed to LoRa
- **Non-Mesh Clients**: Read-only access (useful for monitoring applications and network visualization)
- **Permission Caching**: Permissions are cached with TTL to reduce database load

## Development

### Project Structure

- `cmd/server/` - Main server application
- `pkg/meshtastic/` - Meshtastic protocol implementation
- `pkg/hooks/` - MQTT server hooks for mesh packet processing
- `pkg/routes/` - Web interface routes
- `pkg/store/` - Database layer
- `pkg/auth/` - Authentication and authorization
- `internal/web/` - Web templates and static files

### Updating Meshtastic Protobufs

To update the Meshtastic protocol definitions:
```bash
go generate ./...
```

## License

[License information to be added]

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Support

For issues and questions specific to the Western PA Mesh network, please contact the network administrators.
