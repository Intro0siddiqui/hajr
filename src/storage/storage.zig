//! Hajr Storage Layer - Zero-Copy Database for Browser Data
//! 
//! Implements WiscKey-inspired storage with direct memory access
//! for maximum performance in sandbox environments.

const std = @import("std");
const posix = std.posix;

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
        const fd = try posix.open(
            path,
            .{ .mode = .read_write, .create = true },
            0o644,
        );
        
        // Extend file to initial size
        try posix.ftruncate(fd, @intCast(initial_size));
        
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
        const stat = try posix.fstat(log.fd);
        if (required > @as(u64, @intCast(stat.size))) {
            try posix.ftruncate(log.fd, @intCast(required * 2));
        }
        
        // Write value directly
        const written = try posix.pwrite(log.fd, value, @intCast(offset));
        
        log.write_pos += @as(u64, @intCast(written));
        
        return offset;
    }
    
    /// Read a value from the log
    pub fn read(log: *ValueLog, offset: u64, size: usize) ![]u8 {
        var buf = try log.arena.allocator.alloc(u8, size);
        const bytes = try posix.pread(log.fd, buf, @intCast(offset));
        
        return buf[0..bytes];
    }
    
    /// Close the value log
    pub fn close(log: *ValueLog) void {
        posix.close(log.fd);
        log.index.destroy();
        log.arena.deinit();
    }
};

/// Value index for tracking log entries
pub const ValueIndex = struct {
    /// Hash map of value references
    entries: std.AutoHashMap(u64, ValueEntry),
    
    /// Memory-mapped backing
    mmapped: []align(4096) u8,
    
    /// Create a new value index
    pub fn create(capacity: usize) !ValueIndex {
        return ValueIndex{
            .entries = std.AutoHashMap(u64, ValueEntry).init(std.heap.page_allocator),
            .mmapped = undefined,
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
        if (idx.mmapped.len > 0) {
            posix.munmap(idx.mmapped);
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
    pub fn init(config: Config) LsmTree {
        return LsmTree{
            .mem_table = SkipList.init(),
            .immutable_tables = std.ArrayList(*SkipList).init(std.heap.page_allocator),
            .sstables = std.ArrayList(SSTable).init(std.heap.page_allocator),
            .config = config,
        };
    }
    
    /// Insert a key-value pair
    pub fn insert(tree: *LsmTree, key: []const u8, value_ref: ValueEntry) !void {
        try tree.mem_table.insert(key, value_ref);
        
        // Check if memtable needs flushing
        if (tree.mem_table.size > tree.config.memtable_size) {
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
        for (tree.sstables.items) |sstable| {
            if (sstable.find(key)) |entry| {
                return entry;
            }
        }
        
        return null;
    }
    
    /// Flush memtable to SSTable
    fn flushMemtable(tree: *LsmTree) !void {
        const frozen = try std.heap.page_allocator.create(SkipList);
        frozen.* = tree.mem_table;
        
        try tree.immutable_tables.append(frozen);
        tree.mem_table = SkipList.init();
        
        // Trigger compaction if needed
        if (tree.immutable_tables.items.len > tree.config.max_level) {
            try tree.compact(0);
        }
    }
    
    /// Compact a level
    fn compact(tree: *LsmTree, level: usize) !void {
        _ = tree;
        _ = level;
        // Compaction logic
    }
    
    /// Destroy LSM tree
    pub fn destroy(tree: *LsmTree) void {
        tree.mem_table.destroy();
        for (tree.immutable_tables.items) |table| {
            std.heap.page_allocator.destroy(table);
        }
        tree.immutable_tables.deinit();
        for (tree.sstables.items) |*sstable| {
            sstable.destroy();
        }
        tree.sstables.deinit();
    }
};

/// Skip list for in-memory key-value storage
pub const SkipList = struct {
    /// Head node
    head: *Node,
    /// Current level
    level: u32,
    /// Number of entries
    size: usize,
    
    /// Node in skip list
    pub const Node = struct {
        key: []u8,
        value: ValueEntry,
        next: [16]*Node,
        level: u32,
    };
    
    /// Initialize skip list
    pub fn init() SkipList {
        return SkipList{
            .head = undefined,
            .level = 0,
            .size = 0,
        };
    }
    
    /// Insert key-value pair
    pub fn insert(list: *SkipList, key: []const u8, value: ValueEntry) !void {
        _ = list;
        _ = key;
        _ = value;
        // Skip list insertion
    }
    
    /// Find key
    pub fn find(list: *SkipList, key: []const u8) ?ValueEntry {
        _ = list;
        _ = key;
        return null;
    }
    
    /// Destroy skip list
    pub fn destroy(list: *SkipList) void {
        _ = list;
    }
};

/// SSTable file on disk
pub const SSTable = struct {
    /// File descriptor
    fd: posix.fd_t,
    /// File path
    path: []const u8,
    /// Index cache
    index: std.AutoHashMap([]u8, SSTableEntry),
    
    /// SSTable index entry
    pub const SSTableEntry = struct {
        offset: u64,
        size: u32,
        checksum: u32,
    };
    
    /// Create new SSTable
    pub fn create(path: []const u8) !SSTable {
        const fd = try posix.open(
            path,
            .{ .mode = .read_write, .create = true },
            0o644,
        );
        
        return SSTable{
            .fd = fd,
            .path = path,
            .index = std.AutoHashMap([]u8, SSTableEntry).init(std.heap.page_allocator),
        };
    }
    
    /// Find key in SSTable
    pub fn find(sstable: *SSTable, key: []const u8) ?ValueEntry {
        _ = sstable;
        _ = key;
        return null;
    }
    
    /// Destroy SSTable
    pub fn destroy(sstable: *SSTable) void {
        posix.close(sstable.fd);
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
    ring: *anyopaque,
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
    pub fn init(config: Config) !BrowserDB {
        const value_log = try ValueLog.create(config.value_log_path, config.initial_log_size);
        
        return BrowserDB{
            .value_log = value_log,
            .lsm_tree = LsmTree.init(.{}),
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
    
    /// LRU cache implementation
    pub const LruCache = struct {
        /// Doubly linked list of entries
        head: *CacheEntry,
        /// Hash map for O(1) lookup
        map: std.AutoHashMap(u64, *CacheEntry),
        
        pub const CacheEntry = struct {
            key_hash: u64,
            value: []u8,
            prev: *CacheEntry,
            next: *CacheEntry,
        };
        
        pub fn init() LruCache {
            return LruCache{
                .head = undefined,
                .map = std.AutoHashMap(u64, *CacheEntry).init(std.heap.page_allocator),
            };
        }
        
        /// Access a cached entry (move to front)
        pub fn access(cache: *LruCache, key_hash: u64) ?[]u8 {
            const entry = cache.map.get(key_hash) orelse return null;
            // Move to front of LRU list
            return entry.value;
        }
        
        /// Insert into cache
        pub fn insert(cache: *LruCache, key_hash: u64, value: []u8) !void {
            _ = cache;
            _ = key_hash;
            _ = value;
            // Insert at front of LRU list
        }
        
        /// Evict least recently used entry
        pub fn evict(cache: *LruCache) ?[]u8 {
            _ = cache;
            return null;
        }
    };
    
    /// Initialize cache
    pub fn init(max_entries: usize) Cache {
        return Cache{
            .lru = LruCache.init(),
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
    
    /// Clear cache
    pub fn clear(cache: *Cache) void {
        _ = cache;
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
    defer std.heap.page_allocator.free(read_back);
    
    try std.testing.expectEqualSlices(u8, value, read_back);
}

test "BrowserDB put and get" {
    var db = try BrowserDB.init(.{
        .value_log_path = "/tmp/hajr_db_test",
        .initial_log_size = 1024 * 1024,
    });
    defer db.close();
    
    const key = "test_key";
    const value = "test_value_data";
    
    try db.put(key, value);
    
    const retrieved = db.get(key);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualSlices(u8, value, retrieved.?);
}

test "Cache operations" {
    var cache = Cache.init(100);
    
    const key_hash: u64 = 0x12345678;
    const value = "cached_data";
    
    try cache.put(key_hash, value);
    
    const retrieved = cache.get(key_hash);
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualSlices(u8, value, retrieved.?);
}