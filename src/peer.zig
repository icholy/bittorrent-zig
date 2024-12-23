const std = @import("std");
const testing = std.testing;
const BencodeValue = @import("./bencode.zig").BencodeValue;

pub const Handshake = struct {
    flags: u64 = 0,
    infohash: [std.crypto.hash.Sha1.digest_length]u8,
    peer_id: [20]u8,

    pub fn write(self: Handshake, writer: anytype) !void {
        try writer.writeByte(19);
        try writer.print("BitTorrent protocol", .{});
        try writer.writeInt(u64, self.flags, .big);
        try writer.writeAll(&self.infohash);
        try writer.writeAll(&self.peer_id);
    }

    pub fn read(reader: anytype) !Handshake {
        const length = try reader.readByte();
        if (length != 19) return error.InvalidHandshake;
        const protocol = try reader.readBytesNoEof(19);
        if (!std.mem.eql(u8, &protocol, "BitTorrent protocol")) return error.InvalidHandshake;
        var handshake: Handshake = undefined;
        handshake.flags = try reader.readInt(u64, .big);
        try reader.readNoEof(&handshake.infohash);
        try reader.readNoEof(&handshake.peer_id);
        return handshake;
    }
};

test "Handshake" {
    var buf: [1 << 10]u8 = undefined;
    var fbs_a = std.io.fixedBufferStream(&buf);
    const a = Handshake{
        .infohash = [_]u8{'A'} ** 20,
        .peer_id = [_]u8{'B'} ** 20,
    };
    try a.write(fbs_a.writer());
    var fbs_b = std.io.fixedBufferStream(&buf);
    const b = try Handshake.read(fbs_b.reader());
    try testing.expectEqualDeep(a, b);
}

pub const PeerMessage = union(enum) {
    bitfield: []const u8,
    interested,
    choke,
    unchoke,
    request: struct {
        index: u32,
        begin: u32,
        length: u32,
    },
    piece: struct {
        index: u32,
        begin: u32,
        block: []const u8,
    },
    extension: struct {
        id: u8,
        value: BencodeValue,
        data: []const u8,
    },

    pub fn read(allocator: std.mem.Allocator, reader: anytype) !PeerMessage {
        const length = try reader.readInt(u32, .big);
        const id = try reader.readByte();
        const payload = try allocator.alloc(u8, length - 1);
        defer allocator.free(payload);
        try reader.readNoEof(payload);
        switch (id) {
            5 => return .{ .bitfield = try allocator.dupe(u8, payload) },
            2 => return .interested,
            0 => return .choke,
            1 => return .unchoke,
            6 => {
                if (payload.len != 12) return error.InvalidPayload;
                return .{
                    .request = .{
                        .index = std.mem.readInt(u32, payload[0..4], .big),
                        .begin = std.mem.readInt(u32, payload[4..8], .big),
                        .length = std.mem.readInt(u32, payload[8..12], .big),
                    },
                };
            },
            7 => {
                if (payload.len < 12) return error.InvalidPayload;
                return .{
                    .piece = .{
                        .index = std.mem.readInt(u32, payload[0..4], .big),
                        .begin = std.mem.readInt(u32, payload[4..8], .big),
                        .block = try allocator.dupe(u8, payload[8..]),
                    },
                };
            },
            20 => {
                if (payload.len < 1) return error.InvalidPayload;
                var token = try BencodeValue.decode(allocator, payload[1..]);
                errdefer token.value.deinit(allocator);
                const data = try allocator.dupe(u8, payload[1 + token.n_bytes ..]);
                return .{
                    .extension = .{
                        .id = payload[0],
                        .value = token.value,
                        .data = data,
                    },
                };
            },
            else => return error.NotImplemented,
        }
    }

    pub fn write(self: PeerMessage, writer: anytype) !void {
        switch (self) {
            .bitfield => |payload| {
                try writer.writeInt(u32, @intCast(1 + payload.len), .big);
                try writer.writeByte(5);
                try writer.writeAll(payload);
            },
            .interested => {
                try writer.writeInt(u32, 1, .big);
                try writer.writeByte(2);
            },
            .choke => {
                try writer.writeInt(u32, 1, .big);
                try writer.writeByte(0);
            },
            .unchoke => {
                try writer.writeInt(u32, 1, .big);
                try writer.writeByte(1);
            },
            .request => |req| {
                try writer.writeInt(u32, 13, .big);
                try writer.writeByte(6);
                try writer.writeInt(u32, req.index, .big);
                try writer.writeInt(u32, req.begin, .big);
                try writer.writeInt(u32, req.length, .big);
            },
            .piece => |piece| {
                try writer.writeInt(u32, @intCast(1 + 8 + piece.block.len), .big);
                try writer.writeByte(7);
                try writer.writeInt(u32, piece.index, .big);
                try writer.writeInt(u32, piece.begin, .big);
                try writer.writeAll(piece.block);
            },
            .extension => |ext| {
                var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                defer arena.deinit();
                var encoded = std.ArrayList(u8).init(arena.allocator());
                try ext.value.encode(encoded.writer());
                try writer.writeInt(u32, @intCast(1 + 1 + encoded.items.len + ext.data.len), .big);
                try writer.writeByte(20);
                try writer.writeByte(ext.id);
                try writer.writeAll(encoded.items);
                try writer.writeAll(ext.data);
            },
        }
    }

    pub fn deinit(self: *PeerMessage, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .interested, .choke, .unchoke, .request => {},
            .bitfield => |payload| allocator.free(payload),
            .piece => |piece| allocator.free(piece.block),
            .extension => |*ext| {
                ext.value.deinit(allocator);
                allocator.free(ext.data);
            },
        }
    }
};

fn testPeerMessageRoundTrip(msg: PeerMessage) !void {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try msg.write(buf.writer());
    var fbs = std.io.fixedBufferStream(buf.items);
    var msg2 = try PeerMessage.read(testing.allocator, fbs.reader());
    defer msg2.deinit(testing.allocator);
    try testing.expectEqualDeep(msg, msg2);
}

test "PeerMessage: round-trip" {
    try testPeerMessageRoundTrip(.interested);
    try testPeerMessageRoundTrip(.{ .bitfield = "test" });
    try testPeerMessageRoundTrip(.choke);
    try testPeerMessageRoundTrip(.unchoke);
    try testPeerMessageRoundTrip(.{ .request = .{ .index = 1, .begin = 2, .length = 3 } });
    try testPeerMessageRoundTrip(.{ .piece = .{ .index = 1, .begin = 2, .block = "test" } });
    try testPeerMessageRoundTrip(.{ .extension = .{ .id = 0, .value = BencodeValue{ .int = 123 }, .data = []u8{} } });
}

test "PeerMessage: bitfield" {
    var buf_in = [_]u8{ 0, 0, 0, 5, 5, 0, 0, 0, 0 };
    var fbs_in = std.io.fixedBufferStream(&buf_in);
    var msg = try PeerMessage.read(testing.allocator, fbs_in.reader());
    defer msg.deinit(testing.allocator);

    var buf_out: [buf_in.len]u8 = undefined;
    var fbs_out = std.io.fixedBufferStream(&buf_out);
    try msg.write(fbs_out.writer());

    try testing.expectEqualSlices(u8, &buf_in, &buf_out);
}

// write the test as if it's implemented
test "PeerMessage: interested" {
    var buf_in = [_]u8{ 0, 0, 0, 1, 2 };
    var fbs_in = std.io.fixedBufferStream(&buf_in);
    var msg = try PeerMessage.read(testing.allocator, fbs_in.reader());
    defer msg.deinit(testing.allocator);

    var buf_out: [buf_in.len]u8 = undefined;
    var fbs_out = std.io.fixedBufferStream(&buf_out);
    try msg.write(fbs_out.writer());
}

pub const PeerParser = struct {
    data: []const u8,
    offset: usize,

    pub fn init(data: []const u8) PeerParser {
        return .{
            .data = data,
            .offset = 0,
        };
    }

    pub fn next(self: *PeerParser) ?std.net.Ip4Address {
        if (self.data.len - self.offset < 6) return null;
        const ip: [4]u8 = self.data[self.offset .. self.offset + 4][0..4].*;
        const port = std.mem.readInt(u16, &self.data[self.offset + 4 .. self.offset + 6][0..2].*, .big);
        self.offset += 6;
        return std.net.Ip4Address.init(ip, port);
    }

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) ![]std.net.Ip4Address {
        if (data.len % 6 != 0) return error.InvalidPeerData;
        var parser = PeerParser.init(data);
        var peers = std.ArrayList(std.net.Ip4Address).init(allocator);
        defer peers.deinit();
        while (parser.next()) |peer| {
            try peers.append(peer);
        }
        return peers.toOwnedSlice();
    }
};

pub const ExtensionHandshake = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(u32),

    pub fn init(allocator: std.mem.Allocator) ExtensionHandshake {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(u32).init(allocator),
        };
    }

    pub fn deinit(self: *ExtensionHandshake) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.map.deinit();
    }

    pub fn add(self: *ExtensionHandshake, extension: []const u8, id: u32) !void {
        const key = try self.allocator.dupe(u8, extension);
        errdefer self.allocator.free(key);
        try self.map.put(key, id);
    }

    pub fn write(self: *ExtensionHandshake, writer: anytype) !void {
        var value = try self.toBencodeValue(self.allocator);
        defer value.deinit(self.allocator);
        try PeerMessage.write(.{ .extension = .{ .id = 0, .value = value, .data = &[_]u8{} } }, writer);
    }

    pub fn read(allocator: std.mem.Allocator, reader: anytype) !ExtensionHandshake {
        var msg = try PeerMessage.read(allocator, reader);
        defer msg.deinit(allocator);
        if (msg != .extension) return error.UnexpectedMessageType;
        var ext = init(allocator);
        errdefer ext.deinit();
        try ext.fromBencodeValue(msg.extension.value);
        return ext;
    }

    fn fromBencodeValue(self: *ExtensionHandshake, value: BencodeValue) !void {
        const m = try value.get("m", .dict);
        var it = m.iterator();
        while (it.next()) |entry| {
            const id = entry.value_ptr.*;
            if (id != .int) return error.WrongType;
            try self.add(entry.key_ptr.*, @intCast(id.int));
        }
    }

    fn toBencodeValue(self: *ExtensionHandshake, allocator: std.mem.Allocator) !BencodeValue {
        var extensions = BencodeValue.initDict(allocator);
        errdefer extensions.deinit(allocator);
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const key = try allocator.dupe(u8, entry.key_ptr.*);
            errdefer allocator.free(key);
            try extensions.dict.put(key, BencodeValue{ .int = entry.value_ptr.* });
        }
        var value = BencodeValue.initDict(allocator);
        const key = try allocator.dupe(u8, "m");
        errdefer allocator.free(key);
        try value.dict.put(key, extensions);
        return value;
    }

    pub fn encode(self: ExtensionHandshake, writer: anytype) !void {
        try BencodeValue.writeDictOpen(writer);
        try BencodeValue.writeString(writer, "m");
        try BencodeValue.writeDictOpen(writer);
        const it = self.map.iterator();
        while (it.next()) |entry| {
            try BencodeValue.writeString(entry.key_ptr.*);
            try BencodeValue.writeInt(entry.value_ptr.*);
        }
        try BencodeValue.writeDictClose(writer);
        try BencodeValue.writeDictClose(writer);
    }
};
