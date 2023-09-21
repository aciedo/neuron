# NEURON

NEURON is Aciedo's internal comms-net and global nervous system. It's an incredibly reliable, low-latency, high-throughput and intelligent mesh network that is designed to get messages from anywhere to anywhere, globally, as quickly as possible, at all times. 

NEURON is designed for 0% message loss, 100% uptime and flat delivery latencies.

This repository is split into a router and a client. The **router** is a operator in the network, and the client uses a HL-QUIC API to connect to routers. In use, PSION is running a NEURON router and each Aciedo service (such as Atlas) uses the client to connect back to PSION. 

## Architecture

### Streams

NEURON's basic communication type is the **stream**. A **stream** is identified by its **topic** and contains an ordered list of **messages**. 

Streams are designed to be used as a pub/sub system, but can be used for any type of communication.

Streams are operated on a regional level, but are accessable globally. In the case of a region failure, a regional stream may be running in a backup region nearby. This is handled automatically by NEURON and won't cause any downtime.

### Networking

NEURON uses HL-QUIC connections to connect routers to one another. These backbone links are referred to as **axons**. Axons use Aciedo's SKI protocol to authenticate every single router. SKI, or Sharded Key Infrastructure, authenticates bare metal servers at the lowest network level to ensure platform security. This means only hardware that Aciedo has authorised can participate in our metal cloud. 

### Persistence

NEURON uses two primitive types of streams: persistent and ephemeral. Persistent streams get stored in ScyllaDB and ephemeral streams don't store messages at all. 

When writing to a persistent stream, the router will wait for Scylla's confirmation (waits on write conf from backup region) before sending to subscribers to respond. 

When writing to an ephemeral stream, the router will skip waiting for Scylla's confirmation.

### Scaling streams

NEURON scales topic capacity through **localised smart partitioning**. 

Topics are partitioned across routers in the region they're created in, but will be automatically migrated to the optimal region for write latency. 

The router operating the topic is the source of truth for the topic, and handles reads and writes to it. Each topic's subscribers are tracked by this router, and it can track individual deliveries of a message to any individual subscription(s) anywhere in the world.

### Data loss

As with the rest of Aciedo's systems, NEURON attempts to tolerate router to individual region failures autonomously without data loss. Topics are replicated twice on region and either once or twice across the closest other regions. 

In reality, NEURON can technically tolerate higher levels of failure autonomously but it's not guaranteed. 

In the case of emergencies where we're aware of imminent region failure, PSION can migrate operations over to other regions with no downtime. 

### Localised smart partitioning

Regions partition topics evenly between routers using XXHash3 and a fixed partition range of 2^16. This allows for efficient healing and extremely fast routing.

The partition a topic is assigned to is the first 16 bits of the topic's hash.

Each partition has individually managed consensus, so while a topic may operate from a single server, it will automatically migrate (inside its parent partition) to another server if the current server fails. 

These partitions are then replicated to one or two backup regions.

#### When a new router joins a region

1. the router determines what partitions it should be responsible for. these are equally split among all nodes.
2. the router adds itself as a replicant for each partition in a "catch-up" state
3. the nodes start streaming their partitions down to the new node
4. when the new node catches up on each partition, it enters the "available" state
5. the old node then decides whether it still is required to keep the partition or not. if it's not a replicant in the new state, it will migrate the partition's operation to the new node and remove the partition from its own state.

#### When a router leaves a region (or crashes)

1. other replicants of the partitions the failed node was responsible for notice the failure within milliseconds due to missing heartbeats (or broken connections)
2. they immediately re-elect leaders for each partition and take over operation of the partition
3. other nodes in the network who are forwarding messages to the failed node will get connection errors and failed heartbeats and will try to send the message to the partition's replicants instead
4. moments later, other nodes receive confirmation of the failed node's failure and will remove it from their routing tables

No downtime is observed during this process. Messages may be delayed by a few milliseconds while NEURON re-establishes control over the partition.

