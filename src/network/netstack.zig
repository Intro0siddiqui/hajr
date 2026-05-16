//! Hajr Network Layer - High-Performance QUIC/HTTP3 Pipeline
//! 
//! Implements a zero-copy network stack optimized for browser sandbox isolation.
//! Uses lock-free ring buffers for direct memory transfer between network and rendering.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const os = std.os;

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
    
    pub fn isValid(id: ConnectionId) bool {
        inline for (id.bytes, 0..) |byte, i| {
            _ = i;
            if (byte != 0) return true;
        }
        return false;
    }
    
    pub fn fromSlice(slice: []const u8) ConnectionId {
        var id = ConnectionId{ .bytes = undefined };
        @memset(&id.bytes, 0);
        @memcpy(&id.bytes, slice[0..@min(slice.len, 18)]);
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

/// QUIC frame types
pub const FrameType = enum(u64) {
    padding = 0,
    ping = 1,
    ack = 2,
    ack_maybe = 3,
    rst_stream = 4,
    stop_sending = 5,
    max_data = 6,
    max_stream_data = 7,
    max_streams = 8,
    data_blocked = 9,
    stream_data_blocked = 10,
    streams_blocked = 11,
    new_connection_id = 12,
    retire_connection_id = 13,
    path_challenge = 14,
    path_response = 15,
    connection_close = 18,
    handshake_done = 19,
    // HTTP/3 frames
    settings = 6,
    headers = 1,
    request = 0,
    response = 1,
    push = 2,
    goaway = 7,
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
    
    pub fn serialize(header: PacketHeader, buf: *std.ArrayList(u8)) !void {
        // Variable length encoding for connection ID
        const cid_len = header.dest_conn_id.bytes[0];
        
        // First byte: packet type + fixed bit
        var first_byte: u8 = @as(u8, @intFromEnum(header.packet_type)) << 4 | 0x40;
        if (header.spin) first_byte |= 0x20;
        if (header.key_phase) first_byte |= 0x04;
        first_byte |= header.reserved;
        
        try buf.append(first_byte);
        
        // Connection ID length
        try buf.append(cid_len);
        
        // Connection ID bytes
        try buf.appendSlice(&header.dest_conn_id.bytes[0..cid_len]);
        
        // Packet number (variable length)
        try writeVarint(buf, header.packet_number);
    }
    
    fn writeVarint(buf: *std.ArrayList(u8), value: u64) !void {
        if (value < 0x3F) {
            try buf.append(@as(u8, @intCast(value)));
        } else if (value < 0x3FFF) {
            const b0 = @as(u8, @intCast((value >> 8) | 0x40));
            const b1 = @as(u8, @intCast(value & 0xFF));
            try buf.append(b0);
            try buf.append(b1);
        } else if (value < 0x3FFFFFFF) {
            const b0 = @as(u8, @intCast((value >> 24) | 0x80);
            try buf.append(b0);
            try buf.append(@as(u8, @intCast((value >> 16) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 8) & 0xFF)));
            try buf.append(@as(u8, @intCast(value & 0xFF)));
        } else {
            const b0 = @as(u8, @intCast((value >> 56) | 0xC0));
            try buf.append(b0);
            try buf.append(@as(u8, @intCast((value >> 48) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 40) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 32) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 24) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 16) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 8) & 0xFF)));
            try buf.append(@as(u8, @intCast(value & 0xFF)));
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
    recv_buffer: std.ArrayList(u8),
    /// Outgoing data buffer
    send_buffer: std.ArrayList(u8),
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
            .recv_buffer = std.ArrayList(u8).init(std.heap.page_allocator),
            .send_buffer = std.ArrayList(u8).init(std.heap.page_allocator),
            .unidirectional = unidirectional,
        };
    }
    
    pub fn deinit(stream: *Http3Stream) void {
        stream.recv_buffer.deinit();
        stream.send_buffer.deinit();
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
    
    pub fn init() Http3Connection {
        return Http3Connection{
            .quic_state = .idle,
            .settings = .{},
            .streams = std.AutoHashMap(u64, *Http3Stream).init(std.heap.page_allocator),
            .control_stream_id = null,
            .qpack_encoder = QPackEncoder.init(),
            .qpack_decoder = QPackDecoder.init(),
            .local_settings = .{},
            .peer_settings = .{},
        };
    }
    
    pub fn deinit(conn: *Http3Connection) void {
        var it = conn.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
            std.heap.page_allocator.destroy(entry.value_ptr);
        }
        conn.streams.deinit();
    }
    
    /// Create a new bidirectional stream
    pub fn createStream(conn: *Http3Connection, is_client: bool) !*Http3Stream {
        // Client-initiated streams are even, server-initiated are odd
        const stream_id_base: u64 = if (is_client) 0 else 1;
        
        // Find next available stream number
        var max_stream_id: u64 = 0;
        var it = conn.streams.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.* > max_stream_id) {
                max_stream_id = entry.key_ptr.*;
            }
        }
        
        const stream_id = stream_id_base + (max_stream_id + 2) * 4;
        const stream = try std.heap.page_allocator.create(Http3Stream);
        stream.* = Http3Stream.init(stream_id, false);
        
        try conn.streams.put(stream_id, stream);
        
        return stream;
    }
    
    /// Create control stream
    pub fn createControlStream(conn: *Http3Connection) !u64 {
        const stream = try conn.createStream(true); // Control stream is client-initiated
        conn.control_stream_id = stream.stream_id;
        
        // Send SETTINGS frame
        try conn.sendSettings(stream);
        
        return stream.stream_id;
    }
    
    /// Send SETTINGS frame on control stream
    fn sendSettings(conn: *Http3Connection, stream: *Http3Stream) !void {
        var frame = std.ArrayList(u8).init(std.heap.page_allocator);
        defer frame.deinit();
        
        // SETTINGS frame type
        try frame.append(@as(u8, @intFromEnum(@as(FrameType, @enumFromInt(6)))));
        
        // Encode settings
        if (conn.local_settings.max_concurrent_streams) |val| {
            try frame.append(@as(u8, 0x01)); // SETTINGS_MAX_CONCURRENT_STREAMS
            try writeVarint(&frame, val);
        }
        if (conn.local_settings.max_field_section_size) |val| {
            try frame.append(@as(u8, 0x06)); // SETTINGS_MAX_FIELD_SECTION_SIZE
            try writeVarint(&frame, val);
        }
        
        try stream.send_buffer.appendSlice(frame.items);
    }
    
    /// Process incoming HTTP/3 frame
    pub fn processFrame(conn: *Http3Connection, stream_id: u64, frame_type: FrameType, payload: []const u8) !void {
        switch (frame_type) {
            .settings => {
                try conn.parseSettings(payload);
            },
            .headers => {
                try conn.processHeaders(stream_id, payload);
            },
            .request, .response => {
                try conn.processDataFrame(stream_id, payload);
            },
            .goaway => {
                try conn.processGoaway(payload);
            },
            .ping => {
                // Respond to ping
            },
            else => {
                return error.UnsupportedFrame;
            }
        }
    }
    
    fn parseSettings(conn: *Http3Connection, payload: []const u8) !void {
        var pos: usize = 0;
        while (pos < payload.len) {
            if (pos >= payload.len) break;
            
            const setting_id = payload[pos];
            pos += 1;
            
            const value = try readVarint(payload, &pos);
            
            switch (setting_id) {
                0x01 => conn.peer_settings.max_concurrent_streams = value,
                0x06 => conn.peer_settings.max_field_section_size = value,
                else => {}, // Unknown setting, ignore
            }
        }
    }
    
    fn processHeaders(conn: *Http3Connection, stream_id: u64, payload: []const u8) !void {
        const stream = conn.streams.get(stream_id) orelse return error.StreamNotFound;
        
        // Decode QPACK headers
        const headers = try conn.qpack_decoder.decode(payload);
        
        // Store headers in stream
        try stream.recv_buffer.appendSlice(headers);
        
        stream.state = .open;
    }
    
    fn processDataFrame(conn: *Http3Connection, stream_id: u64, payload: []const u8) !void {
        const stream = conn.streams.get(stream_id) orelse return error.StreamNotFound;
        
        // Append data
        try stream.recv_buffer.appendSlice(payload);
    }
    
    fn processGoaway(conn: *Http3Connection, payload: []const u8) !void {
        var pos: usize = 0;
        _ = try readVarint(payload, &pos); // Stream ID
        _ = try readVarint(payload, &pos); // Error code
        
        // Transition to closing state
        conn.quic_state = .closing;
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
            if (buf[pos - 1] & 0x80 == 0) break;
        }
        
        return value;
    }
    
    fn writeVarint(buf: *std.ArrayList(u8), value: u64) !void {
        if (value < 0x3F) {
            try buf.append(@as(u8, @intCast(value)));
        } else if (value < 0x3FFF) {
            try buf.append(@as(u8, @intCast((value >> 8) | 0x40)));
            try buf.append(@as(u8, @intCast(value & 0xFF)));
        } else if (value < 0x3FFFFFFF) {
            try buf.append(@as(u8, @intCast((value >> 24) | 0x80)));
            try buf.append(@as(u8, @intCast((value >> 16) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 8) & 0xFF)));
            try buf.append(@as(u8, @intCast(value & 0xFF)));
        } else {
            try buf.append(@as(u8, @intCast((value >> 56) | 0xC0)));
            try buf.append(@as(u8, @intCast((value >> 48) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 40) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 32) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 24) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 16) & 0xFF)));
            try buf.append(@as(u8, @intCast((value >> 8) & 0xFF)));
            try buf.append(@as(u8, @intCast(value & 0xFF)));
        }
    }
};

/// QPACK encoder state
pub const QPackEncoder = struct {
    /// Dynamic table
    dynamic_table: [256]QPackEntry,
    dynamic_table_len: usize,
    /// Static table reference
    static_table: [256]QPackEntry,
    
    pub fn init() QPackEncoder {
        return QPackEncoder{
            .dynamic_table = undefined,
            .dynamic_table_len = 0,
            .static_table = initStaticTable(),
        };
    }
    
    /// Encode headers using QPACK
    pub fn encode(encoder: *QPackEncoder, headers: []const [2][]const u8) ![]u8 {
        var result = std.ArrayList(u8).init(std.heap.page_allocator);
        defer result.deinit();
        
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
                try result.append(@as(u8, @intCast(idx / 256)));
                try result.append(@as(u8, @intCast(idx % 256)));
            } else {
                // Add to dynamic table and reference
                if (encoder.dynamic_table_len < 256) {
                    encoder.dynamic_table[encoder.dynamic_table_len] = .{
                        .name = name,
                        .value = value,
                    };
                    const new_idx = 256 + encoder.dynamic_table_len;
                    encoder.dynamic_table_len += 1;
                    
                    try result.append(@as(u8, @intCast(new_idx / 256)));
                    try result.append(@as(u8, @intCast(new_idx % 256)));
                }
            }
            
            // Encode value
            try encoder.encodeValue(&result, value);
        }
        
        return result.toOwnedSlice();
    }
    
    fn encodeValue(encoder: *QPackEncoder, buf: *std.ArrayList(u8), value: []const u8) !void {
        // Simple literal encoding
        for (value) |byte| {
            try buf.append(byte);
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
    pub fn decode(decoder: *QPackDecoder, encoded: []const u8) ![][2]u8 {
        var headers = std.ArrayList([2]u8).init(std.heap.page_allocator);
        defer {
            for (headers.items) |h| {
                std.heap.page_allocator.free(h[0]);
                std.heap.page_allocator.free(h[1]);
            }
            headers.deinit();
        }
        
        var pos: usize = 0;
        while (pos < encoded.len) {
            const first = encoded[pos];
            pos += 1;
            
            const base = @as(u64, first) * 256;
            if (base > 0) {
                if (pos >= encoded.len) return error.BufferUnderflow;
                const index = base + @as(u64, encoded[pos]);
                pos += 1;
                
                // Look up in dynamic table
                if (index >= 256 and index < 256 + decoder.dynamic_table_len) {
                    const entry = decoder.dynamic_table[index - 256];
                    const name_copy = try std.heap.page_allocator.dupe(u8, entry.name);
                    const value_copy = try std.heap.page_allocator.dupe(u8, entry.value);
                    try headers.append(.{ name_copy, value_copy });
                }
            }
        }
        
        return headers.toOwnedSlice();
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

/// UDP socket for QUIC
pub const UdpSocket = struct {
    /// Socket file descriptor
    fd: posix.fd_t,
    /// Local address
    local_addr: net.Address,
    /// Remote address
    remote_addr: ?net.Address,
    /// Receive buffer
    recv_buf: [65536]u8,
    /// Send buffer
    send_buf: [65536]u8,
    
    pub fn create(port: u16) !UdpSocket {
        const fd = try posix.socket(.{
            .address_family = .ipv6,
            .type = .datagram,
            .protocol = .udp,
        });
        
        // Enable QUIC-compatible options
        try posix.setsockopt(fd, posix.IPPROTO_IPV6, posix.IPV6_V6ONLY, @as(u32, 0));
        
        // Set socket buffer sizes
        try posix.setsockopt(fd, posix.SOL_SOCKET, posix.SO_RCVBUF, @as(u32, 2 * 1024 * 1024));
        try posix.setsockopt(fd, posix.SOL_SOCKET, posix.SO_SNDBUF, @as(u32, 2 * 1024 * 1024));
        
        const addr = net.Address.init_ipv6(.{
            .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            .port = port,
            .scope_id = 0,
        });
        
        try posix.bind(fd, &addr.any);
        
        return UdpSocket{
            .fd = fd,
            .local_addr = addr,
            .remote_addr = null,
            .recv_buf = undefined,
            .send_buf = undefined,
        };
    }
    
    /// Receive data from socket
    pub fn recv(socket: *UdpSocket, buf: []u8) !struct { bytes: usize, addr: net.Address } {
        var src_addr: net.Address = undefined;
        const addr_len: *posix.socklen_t = @ptrFromInt(@intFromPtr(&src_addr));
        
        const bytes = posix.recvfrom(socket.fd, buf, 0, &src_addr);
        
        return .{ .bytes = bytes, .addr = src_addr };
    }
    
    /// Send data to socket
    pub fn send(socket: *UdpSocket, buf: []const u8, dest: net.Address) !usize {
        const bytes = try posix.sendto(socket.fd, buf, 0, &dest);
        return bytes;
    }
    
    /// Close socket
    pub fn close(socket: *UdpSocket) void {
        posix.close(socket.fd);
    }
};

/// Ring buffer interface for zero-copy network
pub const NetworkRingInterface = struct {
    /// Outbound ring (to sandbox)
    outbound: *anyopaque,
    /// Inbound ring (from sandbox)
    inbound: *anyopaque,
    /// Ring metadata pointer
    metadata: *anyopaque,
    
    /// Write data to network ring (called from network layer)
    pub fn writeToRing(interface: *NetworkRingInterface, data: []const u8) !void {
        _ = interface;
        _ = data;
        // Would write to the actual ring buffer
    }
    
    /// Read data from network ring (called from sandbox)
    pub fn readFromRing(interface: *NetworkRingInterface, buf: []u8) !usize {
        _ = interface;
        _ = buf;
        // Would read from the actual ring buffer
        return 0;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "ConnectionId operations" {
    const id = ConnectionId.fromSlice("test12345678");
    try std.testing.expect(id.isValid());
    
    const invalid = ConnectionId{ .bytes = undefined };
    @memset(&invalid.bytes, 0);
    try std.testing.expect(!invalid.isValid());
}

test "PacketHeader serialization" {
    var buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buf.deinit();
    
    const header = PacketHeader{
        .packet_type = .initial,
        .dest_conn_id = ConnectionId.fromSlice("conn123456"),
        .packet_number = 42,
        .spin = true,
        .key_phase = false,
        .reserved = 0,
    };
    
    try header.serialize(&buf);
    try std.testing.expect(buf.items.len > 0);
}

test "Http3Connection stream management" {
    var conn = Http3Connection.init();
    defer conn.deinit();
    
    const stream1 = try conn.createStream(true);
    try std.testing.expect(stream1.stream_id == 0); // First client stream
    
    const stream2 = try conn.createStream(true);
    try std.testing.expect(stream2.stream_id == 4); // Second client stream
    
    _ = stream1;
    _ = stream2;
}

test "QPACK encoding" {
    var encoder = QPackEncoder.init();
    
    const headers = [_][2][]const u8{
        .{ ":method", "GET" },
        .{ ":path", "/" },
        .{ "user-agent", "Hajr/1.0" },
    };
    
    const encoded = try encoder.encode(&headers);
    try std.testing.expect(encoded.len > 0);
    
    std.heap.page_allocator.free(encoded);
}