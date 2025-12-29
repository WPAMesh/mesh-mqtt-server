# Gateway Connectivity Issue - Root Cause Analysis

## Summary
Gateway nodes are experiencing connectivity issues after several days of continuous operation. This analysis identifies the root cause and explains the validation logic in depth.

## Root Cause

**The verification renewal mechanism is event-driven rather than time-driven, causing verification to expire when gateway nodes remain connected for extended periods without sending NODEINFO packets.**

## Detailed Analysis

### Validation Logic Overview

Gateway nodes must satisfy ALL of the following conditions to be considered valid (`pkg/models/client_details.go:129-139`):

1. **Gateway permission granted** - `ValidGWChecker()` returns true (checks database with 15-minute cache)
2. **NodeDetails exists** - Node information has been received
3. **Not using proxy** - Direct connection, not proxied through mobile app
4. **Downlink verified** - `IsDownlinkVerified()` returns true
5. **Using gateway topic** - Topic ends with `/Gateway`
6. **Valid node role** - Role is not empty, CLIENT_MUTE, or ROUTER_CLIENT

### The Critical Flaw: Downlink Verification Expiry

#### Expiration Timing (`pkg/models/client_details.go:15-21`)
```go
const (
    MaxValidationAge = 3 * 24 * time.Hour  // 3 days - VERIFICATION EXPIRES
    ChannelVerifyTimeout = 60 * time.Second
    MaxVerifyTimeout = 15 * time.Minute
)
```

#### Verification Check (`pkg/models/client_details.go:215-221`)
```go
func (c *NodeInfo) IsDownlinkVerified() bool {
    if c.VerifiedDate != nil {
        expireDate := c.VerifiedDate.Add(MaxValidationAge)
        return time.Now().Before(expireDate)  // Returns false after 3 days!
    }
    return false
}
```

### When Verification Renewal Occurs

Verification renewal is triggered **ONLY** in these specific scenarios (`pkg/hooks/meshhook.go:445`):

1. **Client authenticates** (line 195) - Only happens on initial connection or reconnection
2. **NODEINFO packet received** (packet_interceptor.go:182) - Depends on node sending NODEINFO
3. **Root topic set from subscription** (line 510) - Only on first subscribe
4. **Root topic set from publish** (line 627) - Only on first publish
5. **Channel verification timeout** (line 705) - Only during active verification attempt

The renewal check condition:
```go
shouldReq := cd.IsUsingGatewayTopic() &&
             !cd.IsPendingVerification() &&
             (!cd.IsDownlinkVerified() || cd.IsExpiringSoon() || force)
```

Where `IsExpiringSoon()` triggers at 1 day (MaxValidationAge / 3):
```go
func (c *NodeInfo) IsExpiringSoon() bool {
    if c.VerifiedDate != nil {
        expireDate := c.VerifiedDate.Add(MaxValidationAge / 3)  // 1 day
        return time.Now().After(expireDate)
    }
    return true
}
```

### The Problem Scenario

1. **Day 0**: Gateway connects, gets verified successfully
2. **Day 1-2**: Gateway operates normally, verification is still valid
3. **Day 2+**: Verification enters "expiring soon" state (> 1 day old)
4. **Day 3**: If no NODEINFO packet has been received, verification expires
5. **Result**: Gateway becomes invalid, causing connectivity issues

### Why This Happens After "Several Days"

The 3-day expiration period precisely matches the reported symptom timeline. The issue manifests when:

- Gateway nodes with stable connections don't reconnect for > 3 days
- Gateway firmware doesn't broadcast NODEINFO packets frequently enough
- No other events trigger the verification renewal check

### Missing Component

**The README.md claims:** "Nodes are periodically re-verified to ensure ongoing connectivity" (line 149)

**Reality:** There is NO periodic background task that checks connected clients for expiring verification. The only time-based check is the SSE heartbeat for web UI updates (`pkg/routes/sse.go:106`), which is unrelated to gateway verification.

## Impact

When a gateway's verification expires:

1. `IsValidGateway()` returns false
2. Gateway messages are redirected to non-gateway topics
3. Other gateways don't receive messages from the expired gateway
4. Mapping software sees duplicate messages
5. Gateway effectively loses connectivity to the mesh network

## Solution Requirements

A fix needs to implement one of these approaches:

1. **Periodic verification task** - Background goroutine that checks all connected clients every hour and triggers re-verification for clients with `IsExpiringSoon() == true`

2. **Extend verification period** - Increase MaxValidationAge to a longer period (e.g., 7 or 30 days)

3. **Proactive keepalive** - Server sends periodic NODEINFO requests to all connected gateways regardless of verification status

4. **Hybrid approach** - Combine periodic checks with opportunistic renewal on packet reception

## Key Files Involved

- `pkg/models/client_details.go:15-21` - Validation age constants
- `pkg/models/client_details.go:129-139` - IsValidGateway() logic
- `pkg/models/client_details.go:215-229` - Verification expiry checks
- `pkg/hooks/meshhook.go:435-471` - TryVerifyNode() method
- `pkg/hooks/packet_interceptor.go:128-213` - processNodeInfo() handler
- `pkg/store/users.go:136-147` - IsGatewayAllowed() with 15-min cache

## Database Cache Behavior

The gateway permission cache (`pkg/store/users.go:35-47`) has a 15-minute TTL:
```go
gatewayCache *ttlcache.Cache[int, bool]  // 15-minute TTL
```

This means permission changes take up to 15 minutes to propagate to active connections, but this is unrelated to the 3-day verification expiry issue.

## Conclusion

The gateway connectivity issues after several days are caused by the lack of a periodic verification renewal mechanism, combined with the 3-day verification expiry. The system relies entirely on NODEINFO packet reception to trigger re-verification, which is insufficient for stable, long-running gateway connections.
