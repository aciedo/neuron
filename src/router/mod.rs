mod net;

// As consensus happens at a partition level rather than a topic level, each
// partition gets its own task. NEURON's implementation considers locks to slow
// down the system, so we try to reduce their use as much as possible. This task
// exclusively controls the partition's state machine, and is responsible for
// handling all messages.

// Some functionality inside partitions is delegated to additional tasks, such
// as sending topic updates to subscribers and tracking message delivery. This
// ensures that the main state machine loop inside each partition doesn't get
// blocked. The state machine loop can process much faster than the network can
// deliver messages, so subscriber delivery is tracked on a per-publish basis by
// the networking task and queued for delivery. A highly synchronous partition
// core with delegated IO ensures extreme efficiency on a
// partition-per-partition basis.

// NEURON's architecture is designed to scale linearly per core, limited
// ultimately by networking alone, given appropriate CPU cores for the number of
// partitions. Theoretically, you could reach CPU frequency limits after this,
// but this will likely be in the 80gbps+ per partition range. You'd have to be
// breaching 5Tbps+ per cluster to even approach this sort of limit.
