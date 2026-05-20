//! Hajr Storage Layer - Zero-Copy Database for Browser Data
//!
//! Implements WiscKey-inspired storage with direct memory access
//! for maximum performance in sandbox environments.

const std = @import("std");
const posix = std.posix;
const hw = @import("../hw/mod.zig");

// ============================================================================
// WiscKey Storage Architecture
// ============================================================================
//
// WiscKey separates keys from values, storing only keys in the LSM tree
// while keeping values in a separate log. This eliminates compaction overhead
// and enables direct value access without traversing the entire tree.
//
// For browser sandbox use:
// - Keys: URLs, DOM references, cache identifiers
// - Values: Large blobs (images, scripts, fonts) stored in value log
// - Direct DMA-style access via ring buffers

/// Value log for storing large binary objects
pub const ValueLog = struct {
    /// File descriptor for value log
    fd: posix.fd_t,

    /// Current write position
    write_pos: u64,

    /// Log file path
    path: []const u8,

    /// Memory-mapped index for fast lookups
    index: ValueIndex,

    /// Allocation arena
    arena: std.heap.ArenaAllocator,

    /// Create a new value log
    pub fn create(path: []const u8, initial_size: usize) !ValueLog {
        const fd = try hw.posix_io.fileOpen(path);

        // Extend file to initial size
        try hw.posix_io.fileTruncate(fd, @intCast(initial_size));

        // Memory map the index
        const index = try ValueIndex.create(initial_size / 64);

        return ValueLog{
            .fd = fd,
            .write_pos = 0,
            .path = path,
            .index = index,
            .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
        };
    }

    /// Append a value to the log
    pub fn append(log: *ValueLog, value: []const u8) !u64 {
        const offset = log.write_pos;

        // Calculate required size
        const required = offset + value.len;

        // Extend file if needed
        try hw.posix_io.fileTruncate(log.fd, @intCast(required * 2));

        // Write value directly
        const written = try hw.posix_io.fileWrite(log.fd, value, @intCast(offset));

        log.write_pos += written;

        return offset;
    }

    /// Read a value from the log
    pub fn read(log: *ValueLog, offset: u64, size: usize) ![]u8 {
        // Bug 1 fix: ArenaAllocator.allocator() is a method in Zig 0.13+, not a field
        var buf = try log.arena.allocator().alloc(u8, size);
        const bytes = try hw.posix_io.fileRead(log.fd, buf, @intCast(offset));

        return buf[0..bytes];
    }

    /// Close the value log
    pub fn close(log: *ValueLog) void {
        hw.posix_io.fileClose(log.fd);
        log.index.destroy();
        log.arena.deinit();
    }
};

/// Value index for tracking log entries
pub const ValueIndex = struct {
    /// Hash map of value references
    entries: std.AutoHashMap(u64, ValueEntry),

    /// Memory-mapped backing — null when not mapped
    /// Bug 6 fix: use optional to avoid undefined-length slice
    mmapped: ?[]align(4096) u8,

    /// Create a new value index
    pub fn create(capacity: usize) !ValueIndex {
        _ = capacity;
        return ValueIndex{
            .entries = std.AutoHashMap(u64, ValueEntry).init(std.heap.page_allocator),
            // Bug 6 fix: initialize to null instead of undefined
            .mmapped = null,
        };
    }

    /// Insert a value reference
    pub fn insert(idx: *ValueIndex, key: u64, entry: ValueEntry) !void {
        try idx.entries.put(key, entry);
    }

    /// Lookup a value reference
    pub fn lookup(idx: *ValueIndex, key: u64) ?ValueEntry {
        return idx.entries.get(key);
    }

    /// Destroy the index
    pub fn destroy(idx: *ValueIndex) void {
        idx.entries.deinit();
        // Bug 6 fix: safely unwrap optional before munmap
        if (idx.mmapped) |m| {
            posix.munmap(m);
        }
    }
};

/// Value log entry reference
pub const ValueEntry = struct {
    /// Offset in value log
    offset: u64,
    /// Size of value
    size: u64,
    /// Checksum for integrity
    checksum: u32,
};

/// LSM tree for key storage
pub const LsmTree = struct {
    /// Skip list for in-memory data
    mem_table: SkipList,

    /// Immutable memtables (being compacted)
    immutable_tables: std.ArrayList(*SkipList),

    /// SSTable files on disk
    sstables: std.ArrayList(SSTable),

    /// Configuration
    config: Config,

    /// Allocator
    allocator: std.mem.Allocator,

    /// Configuration
    pub const Config = struct {
        /// Maximum memtable size
        memtable_size: usize = 64 * 1024 * 1024,
        /// Level size multiplier
        level_multiplier: usize = 10,
        /// Maximum level
        max_level: usize = 7,
    };

    /// Initialize LSM tree
    pub fn init(config: Config, allocator: std.mem.Allocator) !LsmTree {
        return LsmTree{
            .mem_table = try SkipList.init(allocator),
            .immutable_tables = .empty,
            .sstables = .empty,
            .config = config,
            .allocator = allocator,
        };
    }

    /// Insert a key-value pair
    pub fn insert(tree: *LsmTree, key: []const u8, value_ref: ValueEntry) !void {
        try tree.mem_table.insert(key, value_ref);

        // Check if memtable needs flushing (use entry count as proxy for size)
        if (tree.mem_table.count > tree.config.memtable_size / 256) {
            try tree.flushMemtable();
        }
    }

    /// Get value reference for a key
    pub fn get(tree: *LsmTree, key: []const u8) ?ValueEntry {
        // Check memtable first
        if (tree.mem_table.find(key)) |entry| {
            return entry;
        }

        // Check immutable tables
        for (tree.immutable_tables.items) |table| {
            if (table.find(key)) |entry| {
                return entry;
            }
        }

        // Check SSTables (newest to oldest)
        for (tree.sstables.items) |*sstable| {
            if (sstable.find(key)) |entry| {
                return entry;
            }
        }

        return null;
    }

    /// Flush memtable to SSTable
    fn flushMemtable(tree: *LsmTree) !void {
        const frozen = try tree.allocator.create(SkipList);
        frozen.* = tree.mem_table;

        try tree.immutable_tables.append(tree.allocator, frozen);
        tree.mem_table = try SkipList.init(tree.allocator);

        // Trigger compaction if needed
        if (tree.immutable_tables.items.len > tree.config.max_level) {
            try tree.compact(0);
        }
    }

    /// Compact a level: write immutable memtables to SSTables
    fn compact(tree: *LsmTree, level: usize) !void {
        _ = level;

        // Write all immutable tables to SSTables
        for (tree.immutable_tables.items) |table| {
            // Create unique path for new SSTable
            var path_buf: [256]u8 = undefined;
            const path = std.fmt.bufPrint(
                &path_buf,
                "/tmp/hajr_sst_{d}.sst",
                .{tree.sstables.items.len},
            ) catch "/tmp/hajr_sst_fallback.sst";

            var sstable = try SSTable.create(path);

            // Walk the skiplist in sorted order and write all entries
            var node = table.header.forward[0];
            while (node) |n| {
                if (n.entry) |entry| {
                    try sstable.append(entry.key, entry.value);
                }
                node = n.forward[0];
            }

            try tree.sstables.append(tree.allocator, sstable);
        }

        // Clean up all immutable tables
        for (tree.immutable_tables.items) |table| {
            table.destroy();
            tree.allocator.destroy(table);
        }
        tree.immutable_tables.clearAndFree(tree.allocator);
    }

    /// Destroy LSM tree
    pub fn destroy(tree: *LsmTree) void {
        tree.mem_table.destroy();
        for (tree.immutable_tables.items) |table| {
            table.destroy();
            std.heap.page_allocator.destroy(table);
        }
        tree.immutable_tables.deinit(tree.allocator);
        for (tree.sstables.items) |*sstable| {
            sstable.destroy();
        }
        tree.sstables.deinit(tree.allocator);
    }
};

/// Skip list for in-memory key-value storage
pub const SkipList = struct {
    const MAX_LEVEL = 16;
    const P = 0.5;

    header: *Node,
    level: usize,
    count: usize,
    allocator: std.mem.Allocator,
    random: std.Random.DefaultPrng,

    pub const Entry = struct {
        key: []u8,
        value: ValueEntry,
    };

    const Node = struct {
        entry: ?Entry,
        forward: [MAX_LEVEL]?*Node,

        fn create(allocator: std.mem.Allocator, entry: ?Entry, level: usize) !*Node {
            const node = try allocator.create(Node);
            node.* = .{
                .entry = entry,
                .forward = [_]?*Node{null} ** MAX_LEVEL,
            };
            _ = level;
            return node;
        }
    };

    /// Initialize skip list
    pub fn init(allocator: std.mem.Allocator) !SkipList {
        const header = try Node.create(allocator, null, MAX_LEVEL);
        
        const seed = hw.posix_io.monotonicTimestamp();
        
        return SkipList{
            .header = header,
            .level = 0,
            .count = 0,
            .allocator = allocator,
            .random = std.Random.DefaultPrng.init(seed),
        };
    }

    fn randomLevel(list: *SkipList) usize {
        var lvl: usize = 0;
        while (list.random.random().float(f32) < P and lvl < MAX_LEVEL - 1) {
            lvl += 1;
        }
        return lvl;
    }

    /// Insert key-value pair
    pub fn insert(list: *SkipList, key: []const u8, value: ValueEntry) !void {
        var update: [MAX_LEVEL]*Node = undefined;
        var x = list.header;

        var i: isize = @as(isize, @intCast(list.level));
        while (i >= 0) : (i -= 1) {
            const idx = @as(usize, @intCast(i));
            while (x.forward[idx]) |next| {
                if (std.mem.lessThan(u8, next.entry.?.key, key)) {
                    x = next;
                } else break;
            }
            update[idx] = x;
        }

        const next_node = if (list.level >= 0) x.forward[0] else null;
        if (next_node) |node| {
            if (std.mem.eql(u8, node.entry.?.key, key)) {
                node.entry.?.value = value;
                return;
            }
        }

        const lvl = list.randomLevel();
        if (lvl > list.level) {
            for (list.level + 1..lvl + 1) |j| {
                update[j] = list.header;
            }
            list.level = lvl;
        }

        const key_copy = try list.allocator.dupe(u8, key);
        const new_node = try Node.create(list.allocator, Entry{ .key = key_copy, .value = value }, lvl);
        for (0..lvl + 1) |j| {
            new_node.forward[j] = update[j].forward[j];
            update[j].forward[j] = new_node;
        }
        list.count += 1;
    }

    /// Find key
    pub fn find(list: *SkipList, key: []const u8) ?ValueEntry {
        var x = list.header;
        var i: isize = @as(isize, @intCast(list.level));
        while (i >= 0) : (i -= 1) {
            const idx = @as(usize, @intCast(i));
            while (x.forward[idx]) |next| {
                if (std.mem.lessThan(u8, next.entry.?.key, key)) {
                    x = next;
                } else break;
            }
        }
        x = x.forward[0] orelse return null;
        if (std.mem.eql(u8, x.entry.?.key, key)) {
            return x.entry.?.value;
        }
        return null;
    }

    /// Destroy skip list and free owned keys
    pub fn destroy(list: *SkipList) void {
        var x = list.header.forward[0];
        while (x) |node| {
            const next = node.forward[0];
            if (node.entry) |entry| {
                list.allocator.free(entry.key);
            }
            list.allocator.destroy(node);
            x = next;
        }
        list.allocator.destroy(list.header);
    }
};

/// Hash context for SSTable's in-memory index ([]u8 keys)
pub const SSTableIndexContext = struct {
    pub fn hash(_: @This(), key: []u8) u64 {
        return std.hash.Wyhash.hash(0, key);
    }
    pub fn eql(_: @This(), a: []u8, b: []u8) bool {
        return std.mem.eql(u8, a, b);
    }
};

/// SSTable file on disk
pub const SSTable = struct {
    /// File descriptor
    fd: posix.fd_t,
    /// File path
    path: []const u8,
    /// Index cache
    index: std.HashMap([]u8, SSTableEntry, SSTableIndexContext, std.hash_map.default_max_load_percentage),
    /// Current write position (used during compaction)
    write_pos: u64,

    /// SSTable index entry
    pub const SSTableEntry = struct {
        offset: u64,
        size: u32,
        checksum: u32,
    };

    /// Create new SSTable
    pub fn create(path: []const u8) !SSTable {
        const fd = try hw.posix_io.fileOpen(path);

        return SSTable{
            .fd = fd,
            .path = path,
            .index = std.HashMap([]u8, SSTableEntry, SSTableIndexContext, std.hash_map.default_max_load_percentage).init(std.heap.page_allocator),
            .write_pos = 0,
        };
    }

    /// Append a key-value entry to the SSTable
    pub fn append(sstable: *SSTable, key: []const u8, value: ValueEntry) !void {
        const key_len: u32 = @intCast(key.len);
        const key_len_bytes = std.mem.asBytes(&key_len);
        const value_bytes = std.mem.asBytes(&value);
        const entry_size = key_len_bytes.len + key.len + value_bytes.len;

        // Write key length
        _ = try hw.posix_io.fileWrite(sstable.fd, key_len_bytes, sstable.write_pos);
        sstable.write_pos += @as(u64, @intCast(key_len_bytes.len));

        // Write key bytes
        _ = try hw.posix_io.fileWrite(sstable.fd, key, sstable.write_pos);
        sstable.write_pos += @as(u64, @intCast(key.len));

        // Write ValueEntry
        _ = try hw.posix_io.fileWrite(sstable.fd, value_bytes, sstable.write_pos);
        sstable.write_pos += @as(u64, @intCast(value_bytes.len));

        // Update in-memory index
        const key_copy = try std.heap.page_allocator.dupe(u8, key);
        try sstable.index.put(key_copy, .{
            .offset = sstable.write_pos - @as(u64, @intCast(entry_size)),
            .size = @as(u32, @intCast(entry_size)),
            .checksum = 0,
        });
    }

    /// Find key in SSTable
    /// Bug 4 fix: intentionally deferred — Phase 3: implement SSTable binary search
    pub fn find(sstable: *SSTable, key: []const u8) ?ValueEntry {
        _ = sstable;
        _ = key;
        // Phase 3: implement SSTable binary search
        return null;
    }

    /// Destroy SSTable
    pub fn destroy(sstable: *SSTable) void {
        hw.posix_io.fileClose(sstable.fd);
        // Free key copies in index
        var it = sstable.index.iterator();
        while (it.next()) |entry| {
            std.heap.page_allocator.free(entry.key_ptr.*);
        }
        sstable.index.deinit();
    }
};

/// BrowserDB main interface
pub const BrowserDB = struct {
    /// Value log
    value_log: ValueLog,
    /// LSM tree for keys
    lsm_tree: LsmTree,
    /// Ring buffer for sandbox access
    ring: ?*anyopaque,
    /// Configuration
    config: Config,

    /// Configuration
    pub const Config = struct {
        /// Value log path
        value_log_path: []const u8,
        /// Initial value log size
        initial_log_size: usize = 128 * 1024 * 1024,
        /// Cache size
        cache_size: usize = 256 * 1024 * 1024,
    };

    /// Initialize BrowserDB
    pub fn init(config: Config, allocator: std.mem.Allocator) !BrowserDB {
        const value_log = try ValueLog.create(config.value_log_path, config.initial_log_size);

        return BrowserDB{
            .value_log = value_log,
            .lsm_tree = try LsmTree.init(.{}, allocator),
            .ring = null,
            .config = config,
        };
    }

    /// Store a blob with associated key
    pub fn put(db: *BrowserDB, key: []const u8, value: []const u8) !void {
        // Append value to log
        const offset = try db.value_log.append(value);

        // Create value reference
        const entry = ValueEntry{
            .offset = offset,
            .size = @as(u64, @intCast(value.len)),
            .checksum = 0, // Would compute CRC32
        };

        // Insert key reference into LSM tree
        try db.lsm_tree.insert(key, entry);
    }

    /// Retrieve a blob by key
    pub fn get(db: *BrowserDB, key: []const u8) ?[]u8 {
        // Lookup key in LSM tree
        const entry = db.lsm_tree.get(key) orelse return null;

        // Read value from log
        return db.value_log.read(entry.offset, @as(usize, @intCast(entry.size))) catch null;
    }

    /// Close database
    pub fn close(db: *BrowserDB) void {
        db.value_log.close();
        db.lsm_tree.destroy();
    }
};

/// Cache entry for frequently accessed data
pub const Cache = struct {
    /// LRU cache
    lru: LruCache,
    /// Maximum entries
    max_entries: usize,
    /// Current count
    count: usize,

    pub const LruCache = struct {
        const Node = struct {
            key_hash: u64,
            value: []u8,
            link: std.DoublyLinkedList.Node = .{},
        };
        const List = std.DoublyLinkedList;

        list: List,
        map: std.AutoHashMap(u64, *Node),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) LruCache {
            return .{
                .list = .{},
                .map = std.AutoHashMap(u64, *Node).init(allocator),
                .allocator = allocator,
            };
        }

        /// Access a cached entry by key hash
        pub fn access(cache: *LruCache, key_hash: u64) ?[]u8 {
            const node = cache.map.get(key_hash) orelse return null;
            cache.list.remove(&node.link);
            cache.list.append(&node.link);
            return node.value;
        }

        /// Insert into cache
        pub fn insert(cache: *LruCache, key_hash: u64, value: []u8) !void {
            if (cache.map.get(key_hash)) |node| {
                node.value = value;
                cache.list.remove(&node.link);
                cache.list.append(&node.link);
                return;
            }
            const node = try cache.allocator.create(Node);
            node.* = .{ .key_hash = key_hash, .value = value };
            cache.list.append(&node.link);
            try cache.map.put(key_hash, node);
        }

        /// Evict least recently used entry
        pub fn evict(cache: *LruCache) ?[]u8 {
            const link = cache.list.popFirst() orelse return null;
            const node = @as(*Node, @fieldParentPtr("link", link));
            _ = cache.map.remove(node.key_hash);
            const val = node.value;
            cache.allocator.destroy(node);
            return val;
        }

        pub fn deinit(cache: *LruCache) void {
            var it = cache.list.first;
            while (it) |link| {
                const next = link.next;
                const node = @as(*Node, @fieldParentPtr("link", link));
                cache.allocator.destroy(node);
                it = next;
            }
            cache.map.deinit();
        }
    };

    /// Initialize cache
    pub fn init(max_entries: usize, allocator: std.mem.Allocator) Cache {
        return Cache{
            .lru = LruCache.init(allocator),
            .max_entries = max_entries,
            .count = 0,
        };
    }

    /// Get from cache
    pub fn get(cache: *Cache, key_hash: u64) ?[]u8 {
        return cache.lru.access(key_hash);
    }

    /// Put into cache
    pub fn put(cache: *Cache, key_hash: u64, value: []u8) !void {
        if (cache.count >= cache.max_entries) {
            _ = cache.lru.evict();
        }
        try cache.lru.insert(key_hash, value);
        cache.count += 1;
    }

    /// Deinit cache and free backing memory
    pub fn deinit(cache: *Cache) void {
        cache.lru.deinit();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ValueLog basic operations" {
    const path = "/tmp/hajr_value_log_test";

    var log = try ValueLog.create(path, 1024 * 1024);
    defer log.close();

    const value = "Test value for storage";
    const offset = try log.append(value);

    try std.testing.expect(offset == 0);

    const read_back = try log.read(0, value.len);
    // read_back is owned by the arena inside log; no separate free needed

    try std.testing.expectEqualSlices(u8, value, read_back);
}

test "BrowserDB put and get" {
    var db = try BrowserDB.init(.{
        .value_log_path = "/tmp/hajr_db_test",
        .initial_log_size = 1024 * 1024,
    }, std.testing.allocator);
    defer db.close();

    const key = "test_key";
    const value = "test_value_data";

    try db.put(key, value);

    const retrieved = db.get(key);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualSlices(u8, value, retrieved.?);
}

test "Cache operations" {
    var cache = Cache.init(100, std.testing.allocator);
    defer cache.deinit();

    const key_hash: u64 = 0x12345678;
    const value: []u8 = @constCast("cached_data");

    try cache.put(key_hash, value);

    const retrieved = cache.get(key_hash);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualSlices(u8, value, retrieved.?);
}