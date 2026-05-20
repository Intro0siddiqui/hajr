//! Hajr Network Layer - High-Performance QUIC/HTTP3 Pipeline
//! 
//! Implements a zero-copy network stack optimized for browser sandbox isolation.
//! Uses lock-free ring buffers for direct memory transfer between network and rendering.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const sandbox = @import("../core/sandbox.zig");

// ============================================================================
// QUIC/HTTP3 Stack Architecture
// ============================================================================
//
// This network layer implements a minimal QUIC stack with HTTP/3 support.
// It's designed for:
// 1. Zero-copy data paths (directly into sandbox ring buffers)
// 2. Minimal latency (no intermediate buffering)
// 3. Hardware-enforced isolation (each connection in protected memory)
//

/// QUIC connection state machine
pub const ConnectionState = enum(u8) {
    /// Connection not yet established
    idle = 0,
    /// Initial handshake in progress
    handshaking = 1,
    /// Connection established
    connected = 2,
    /// Connection active, data transfer
    active = 3,
    /// Closing connection gracefully
    closing = 4,
    /// Connection closed
    closed = 5,
    /// Connection failed
    failed = 6,
};

/// Connection identifier
pub const ConnectionId = extern struct {
    bytes: [18]u8, // Variable length up to 18 bytes
    len: u8,
    
    pub fn isValid(id: ConnectionId) bool {
        return id.len > 0;
    }
    
    pub fn fromSlice(slice: []const u8) ConnectionId {
        var id = ConnectionId{ .bytes = undefined, .len = 0 };
        @memset(&id.bytes, 0);
        const len = @min(slice.len, 18);
        @memcpy(id.bytes[0..len], slice[0..len]);
        id.len = @as(u8, @intCast(len));
        return id;
    }
};

/// QUIC packet types
pub const PacketType = enum(u4) {
    initial = 0,
    zerortt = 1,
    handshake = 2,
    short = 3,
};

/// HTTP/3 frame types (separate enum to avoid duplicate values with FrameType)
pub const Http3FrameType = enum(u64) {
    data = 0,
    headers = 1,
    cancel_push = 3,
    settings = 4,
    push_promise = 5,
    goaway = 7,
    max_push_id = 13,
};

/// QUIC packet header
pub const PacketHeader = struct {
    /// Packet type
    packet_type: PacketType,
    /// Connection ID
    dest_conn_id: ConnectionId,
    /// Packet number
    packet_number: u64,
    /// Spin bit (latency hint)
    spin: bool,
    /// Key phase
    key_phase: bool,
    /// Reserved bits
    reserved: u2,
    
    pub fn serialize(header: PacketHeader, allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8)) !void {
        // Variable length encoding for connection ID
        const cid_len = header.dest_conn_id.len;
        
        // First byte: packet type + fixed bit
        var first_byte: u8 = @as(u8, @intFromEnum(header.packet_type)) << 4 | 0x40;
        if (header.spin) first_byte |= 0x20;
        if (header.key_phase) first_byte |= 0x04;
        first_byte |= header.reserved;
        
        try buf.append(allocator, first_byte);
        
        // Connection ID length
        try buf.append(allocator, cid_len);
        
        // Connection ID bytes
        try buf.appendSlice(allocator, header.dest_conn_id.bytes[0..cid_len]);
        
        // Packet number (variable length)
        try writeVarint(allocator, buf, header.packet_number);
    }
    
    fn writeVarint(allocator: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), value: u64) !void {
        if (value < 0x3F) {
            try buf.append(allocator, @as(u8, @intCast(value)));
        } else if (value < 0x3FFF) {
            const b0 = @as(u8, @intCast((value >> 8) | 0x40));
            const b1 = @as(u8, @intCast(value & 0xFF));
            try buf.append(allocator, b0);
            try buf.append(allocator, b1);
        } else if (value < 0x3FFFFFFF) {
            const b0 = @as(u8, @intCast((value >> 24) | 0x80));
            try buf.append(allocator, b0);
            try buf.append(allocator, @as(u8, @intCast((value >> 16) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast((value >> 8) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast(value & 0xFF)));
        } else {
            const b0 = @as(u8, @intCast((value >> 56) | 0xC0));
            try buf.append(allocator, b0);
            try buf.append(allocator, @as(u8, @intCast((value >> 48) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast((value >> 40) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast((value >> 32) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast((value >> 24) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast((value >> 16) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast((value >> 8) & 0xFF)));
            try buf.append(allocator, @as(u8, @intCast(value & 0xFF)));
        }
    }
};

/// HTTP/3 settings frame
pub const Http3Settings = struct {
    /// Max concurrent streams
    max_concurrent_streams: ?u64 = 100,
    /// Header table size
    max_header_table_size: ?u64 = 0,
    /// Max field section size
    max_field_section_size: ?u64 = 16777216,
    /// QPACK max table capacity
    qpack_max_table_capacity: ?u64 = 0,
    /// QPACK blocked streams
    qpack_blocked_streams: ?u64 = 0,
};

/// HTTP/3 stream handler
pub const Http3Stream = struct {
    /// Stream ID
    stream_id: u64,
    /// Stream state
    state: StreamState,
    /// Incoming data buffer
    recv_buffer: std.ArrayListUnmanaged(u8),
    /// Outgoing data buffer
    send_buffer: std.ArrayListUnmanaged(u8),
    /// Unidirectional or bidirectional
    unidirectional: bool,
    
    pub const StreamState = enum(u8) {
        idle = 0,
        open = 1,
        half_closed_local = 2,
        half_closed_remote = 3,
        closed = 4,
    };
    
    pub fn init(stream_id: u64, unidirectional: bool) Http3Stream {
        return Http3Stream{
            .stream_id = stream_id,
            .state = .idle,
            .recv_buffer = .empty,
            .send_buffer = .empty,
            .unidirectional = unidirectional,
        };
    }
    
    pub fn deinit(stream: *Http3Stream, allocator: std.mem.Allocator) void {
        stream.recv_buffer.deinit(allocator);
        stream.send_buffer.deinit(allocator);
    }
};

/// HTTP/3 connection handler
pub const Http3Connection = struct {
    /// QUIC connection state
    quic_state: ConnectionState,
    /// HTTP/3 settings
    settings: Http3Settings,
    /// Active streams
    streams: std.AutoHashMap(u64, *Http3Stream),
    /// Control stream ID
    control_stream_id: ?u64,
    /// QPACK encoder state
    qpack_encoder: QPackEncoder,
    /// QPACK decoder state
    qpack_decoder: QPackDecoder,
    /// Local settings sent
    local_settings: Http3Settings,
    /// Peer settings received
    peer_settings: Http3Settings,
    /// Allocator
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) Http3Connection {
        return Http3Connection{
            .quic_state = .idle,
            .settings = .{},
            .streams = std.AutoHashMap(u64, *Http3Stream).init(allocator),
            .control_stream_id = null,
            .qpack_encoder = QPackEncoder.init(allocator),
            .qpack_decoder = QPackDecoder.init(),
            .local_settings = .{},
            .peer_settings = .{},
            .allocator = allocator,
        };
    }
    
    pub fn deinit(conn: *Http3Connection) void {
        var it = conn.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(conn.allocator);
            conn.allocator.destroy(entry.value_ptr.*);
        }
        conn.streams.deinit();
        conn.qpack_encoder.deinit();
    }
    
    /// Create a new bidirectional stream
    pub fn createStream(conn: *Http3Connection, is_client: bool) !*Http3Stream {
        // Client-initiated streams are even, server-initiated are odd
        const stream_id_base: u64 = if (is_client) 0 else 1;
        
        // Find next available stream number
        var next_stream_id: u64 = stream_id_base;
        
        while (conn.streams.contains(next_stream_id)) {
            next_stream_id += 4;
        }
        
        const stream = try conn.allocator.create(Http3Stream);
        stream.* = Http3Stream.init(next_stream_id, false);
        
        try conn.streams.put(next_stream_id, stream);
        
        return stream;
    }
    
    fn readVarint(buf: []const u8, pos: *usize) !u64 {
        if (pos.* >= buf.len) return error.BufferUnderflow;
        
        const first = buf[pos.*];
        pos.* += 1;
        
        var value: u64 = first & 0x3F;
        if (first & 0x40 != 0) {
            if (pos.* >= buf.len) return error.BufferUnderflow;
            value = (value << 8) | buf[pos.*];
            pos.* += 1;
        } else if (first & 0x80 == 0) {
            return value;
        }
        
        // Continue reading variable length integer
        while (pos.* < buf.len) {
            value = (value << 8) | buf[pos.*];
            pos.* += 1;
            if (buf[pos.* - 1] & 0x80 == 0) break;
        }
        
        return value;
    }
    
};

/// QPACK encoder state
pub const QPackEncoder = struct {
    /// Dynamic table
    dynamic_table: [256]QPackEntry,
    dynamic_table_len: usize,
    /// Static table reference
    static_table: [256]QPackEntry,
    /// Allocator for dynamic table entries
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) QPackEncoder {
        return QPackEncoder{
            .dynamic_table = undefined,
            .dynamic_table_len = 0,
            .static_table = initStaticTable(),
            .allocator = allocator,
        };
    }
    
    pub fn deinit(encoder: *QPackEncoder) void {
        for (encoder.dynamic_table[0..encoder.dynamic_table_len]) |entry| {
            encoder.allocator.free(entry.name);
            encoder.allocator.free(entry.value);
        }
    }
    
    /// Encode headers using QPACK
    pub fn encode(encoder: *QPackEncoder, headers: []const [2][]const u8) ![]u8 {
        var result: std.ArrayListUnmanaged(u8) = .empty;
        defer result.deinit(encoder.allocator);
        
        for (headers) |header| {
            const name = header[0];
            const value = header[1];
            
            // Try to find in static table first
            var found_idx: ?usize = null;
            for (encoder.static_table, 0..) |entry, i| {
                if (std.mem.eql(u8, entry.name, name)) {
                    found_idx = i;
                    break;
                }
            }
            
            // Try dynamic table if not in static
            if (found_idx == null) {
                for (encoder.dynamic_table[0..encoder.dynamic_table_len], 0..) |entry, i| {
                    if (std.mem.eql(u8, entry.name, name)) {
                        found_idx = 256 + i;
                        break;
                    }
                }
            }
            
            if (found_idx) |idx| {
                // Reference existing entry
                try result.append(encoder.allocator, @as(u8, @intCast(idx / 256)));
                try result.append(encoder.allocator, @as(u8, @intCast(idx % 256)));
            } else {
                // Add to dynamic table and reference
                if (encoder.dynamic_table_len < 256) {
                    encoder.dynamic_table[encoder.dynamic_table_len] = .{
                        .name = try encoder.allocator.dupe(u8, name),
                        .value = try encoder.allocator.dupe(u8, value),
                    };
                    const new_idx = 256 + encoder.dynamic_table_len;
                    encoder.dynamic_table_len += 1;
                    
                    try result.append(encoder.allocator, @as(u8, @intCast(new_idx / 256)));
                    try result.append(encoder.allocator, @as(u8, @intCast(new_idx % 256)));
                }
            }
            
            // Encode value
            try encoder.encodeValue(&result, value);
        }
        
        return result.toOwnedSlice(encoder.allocator);
    }
    
    fn encodeValue(encoder: *QPackEncoder, buf: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
        // Simple literal encoding
        for (value) |byte| {
            try buf.append(encoder.allocator, byte);
        }
    }
    
    fn initStaticTable() [256]QPackEntry {
        // Pre-populate with common HTTP headers
        var table: [256]QPackEntry = undefined;
        
        // Common :authority variations
        table[0] = .{ .name = ":authority", .value = "" };
        table[1] = .{ .name = ":method", .value = "GET" };
        table[2] = .{ .name = ":method", .value = "POST" };
        table[3] = .{ .name = ":path", .value = "/" };
        table[4] = .{ .name = ":scheme", .value = "https" };
        table[5] = .{ .name = ":scheme", .value = "http" };
        table[6] = .{ .name = ":status", .value = "200" };
        table[7] = .{ .name = "content-type", .value = "" };
        table[8] = .{ .name = "user-agent", .value = "" };
        
        return table;
    }
};

/// QPACK decoder state
pub const QPackDecoder = struct {
    /// Dynamic table
    dynamic_table: [256]QPackEntry,
    dynamic_table_len: usize,
    /// Largest referenced entry
    largest_ref: u64 = 0,
    /// Ack frequency state
    ack_frequency: u64 = 0,
    
    pub fn init() QPackDecoder {
        return QPackDecoder{
            .dynamic_table = undefined,
            .dynamic_table_len = 0,
        };
    }
    
    /// Decode QPACK encoded headers
    /// Minimal pass-through stub: returns a copy of the encoded bytes.
    /// Full QPACK decode is Phase 3 work.
    pub fn decode(decoder: *QPackDecoder, encoded: []const u8, allocator: std.mem.Allocator) ![]u8 {
        _ = decoder;
        const result = try allocator.dupe(u8, encoded);
        return result;
    }
};

/// QPACK table entry
pub const QPackEntry = struct {
    name: []const u8,
    value: []const u8,
};

// ============================================================================
// Network Socket and I/O
// ============================================================================


/// Ring buffer interface for zero-copy network
pub const NetworkRingInterface = struct {
    /// Outbound ring (to sandbox)
    outbound: *sandbox.HardenedRingBuffer,
    /// Inbound ring (from sandbox)
    inbound: *sandbox.HardenedRingBuffer,
    
    /// Write data to network ring (called from network layer)
    pub fn writeToRing(interface: *NetworkRingInterface, data: []const u8) !void {
        try interface.outbound.write(data);
    }
    
    /// Read data from network ring (called from sandbox)
    pub fn readFromRing(interface: *NetworkRingInterface, buf: []u8) !usize {
        return try interface.inbound.read(buf);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ConnectionId operations" {
    const id = ConnectionId.fromSlice("test12345678");
    try std.testing.expect(id.isValid());
    
    var invalid = ConnectionId{ .bytes = [_]u8{0} ** 18, .len = 0 };
    try std.testing.expect(!invalid.isValid());
}

test "PacketHeader serialization" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);

    const header = PacketHeader{
        .packet_type = .initial,
        .dest_conn_id = ConnectionId.fromSlice("conn123456"),
        .packet_number = 42,
        .spin = true,
        .key_phase = false,
        .reserved = 0,
    };

    try header.serialize(std.testing.allocator, &buf);
    try std.testing.expect(buf.items.len > 0);
}

test "Http3Connection stream management" {
    var conn = Http3Connection.init(std.testing.allocator);
    defer conn.deinit();
    
    const stream1 = try conn.createStream(true);
    try std.testing.expect(stream1.stream_id == 0); // First client stream
    
    const stream2 = try conn.createStream(true);
    try std.testing.expect(stream2.stream_id == 4); // Second client stream
}

test "QPACK encoding" {
    var encoder = QPackEncoder.init(std.testing.allocator);
    defer encoder.deinit();
    
    const headers = [_][2][]const u8{
        .{ ":method", "GET" },
        .{ ":path", "/" },
        .{ "user-agent", "Hajr/1.0" },
    };
    
    const encoded = try encoder.encode(&headers);
    try std.testing.expect(encoded.len > 0);
    
    std.testing.allocator.free(encoded);
}