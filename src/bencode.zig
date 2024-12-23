const std = @import("std");
const testing = std.testing;

pub const BencodeToken = struct {
    value: BencodeValue,
    n_bytes: usize,
};

pub const BencodeValue = union(enum) {
    string: []const u8,
    int: i64,
    list: std.ArrayList(BencodeValue),
    dict: std.StringArrayHashMap(BencodeValue),

    pub fn initDict(allocator: std.mem.Allocator) BencodeValue {
        return BencodeValue{
            .dict = std.StringArrayHashMap(BencodeValue).init(allocator),
        };
    }

    pub fn deinit(self: *BencodeValue, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .string => |s| allocator.free(s),
            .list => |l| {
                for (l.items) |*v| v.deinit(allocator);
                l.deinit();
            },
            .dict => |*d| {
                var it = d.iterator();
                while (it.next()) |e| {
                    allocator.free(e.key_ptr.*);
                    e.value_ptr.deinit(allocator);
                }
                d.deinit();
            },
            .int => {},
        }
    }

    pub fn encode(self: BencodeValue, writer: anytype) !void {
        switch (self) {
            .string => |s| try writeString(writer, s),
            .int => |i| try writeInt(writer, i),
            .list => |l| {
                try writeListOpen(writer);
                for (l.items) |v| try v.encode(writer);
                try writeListClose(writer);
            },
            .dict => |d| {
                try writeDictOpen(writer);
                var it = d.iterator();
                while (it.next()) |e| {
                    try writeString(writer, e.key_ptr.*);
                    try e.value_ptr.encode(writer);
                }
                try writeDictClose(writer);
            },
        }
    }

    pub fn writeInt(writer: anytype, value: i64) !void {
        try writer.print("i{d}e", .{value});
    }

    pub fn writeString(writer: anytype, value: []const u8) !void {
        try writer.print("{d}:{s}", .{ value.len, value });
    }

    pub fn writeDictOpen(writer: anytype) !void {
        try writer.writeByte('d');
    }

    pub fn writeDictClose(writer: anytype) !void {
        try writer.writeByte('e');
    }

    pub fn writeListOpen(writer: anytype) !void {
        try writer.writeByte('l');
    }

    pub fn writeListClose(writer: anytype) !void {
        try writer.writeByte('e');
    }

    test "encode" {
        try expectEncodedString("4:test", .{ .string = "test" });
        try expectEncodedString("i42e", .{ .int = 42 });

        var list = std.ArrayList(BencodeValue).init(testing.allocator);
        defer list.deinit();
        try list.append(.{ .string = "test" });
        try list.append(.{ .int = 42 });
        try expectEncodedString("l4:testi42ee", .{ .list = list });

        var dict = std.StringArrayHashMap(BencodeValue).init(testing.allocator);
        defer dict.deinit();
        try dict.put("foo", .{ .string = "bar" });
        try dict.put("answer", .{ .int = 42 });
        try expectEncodedString("d3:foo3:bar6:answeri42ee", .{ .dict = dict });
    }

    pub fn find(data: []const u8, key: []const u8) ?usize {
        if (data.len == 0 or data[0] != 'd') {
            return null;
        }
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var offset: usize = 1;
        while (offset < data.len and data[offset] != 'e') {
            var key_token = decode(allocator, data[offset..]) catch return null;
            defer key_token.value.deinit(allocator);
            if (key_token.value != .string) {
                return null;
            }
            offset += key_token.n_bytes;
            if (std.mem.eql(u8, key_token.value.string, key)) {
                return offset;
            }
            var value_token = decode(allocator, data[offset..]) catch return null;
            defer value_token.value.deinit(allocator);
            offset += value_token.n_bytes;
        }
        return null;
    }

    test "find" {
        try testing.expectEqual(null, BencodeValue.find("4:test", "foo"));
        try testing.expectEqual(null, BencodeValue.find("i42e", "foo"));
        try testing.expectEqual(6, BencodeValue.find("d3:foo3:bar5:helloi52ee", "foo").?);
        try testing.expectEqual(18, BencodeValue.find("d3:foo3:bar5:helloi52ee", "hello").?);
    }

    pub fn decode(allocator: std.mem.Allocator, data: []const u8) !BencodeToken {
        if (data.len == 0) {
            return error.InvalidArgument;
        }
        switch (data[0]) {
            '0'...'9' => {
                const colon_idx = std.mem.indexOf(u8, data, ":") orelse {
                    return error.InvalidArgument;
                };
                const string_len = try std.fmt.parseInt(usize, data[0..colon_idx], 10);
                return .{
                    .n_bytes = colon_idx + string_len + 1,
                    .value = .{ .string = try allocator.dupe(u8, data[colon_idx + 1 .. colon_idx + 1 + string_len]) },
                };
            },
            'i' => {
                const e_idx = std.mem.indexOf(u8, data, "e") orelse {
                    return error.InvalidArgument;
                };
                return .{
                    .n_bytes = e_idx + 1,
                    .value = .{ .int = try std.fmt.parseInt(i64, data[1..e_idx], 10) },
                };
            },
            'l' => {
                var offset: usize = 1;
                var list = std.ArrayList(BencodeValue).init(allocator);
                errdefer list.deinit();
                while (offset < data.len and data[offset] != 'e') {
                    var token = try decode(allocator, data[offset..]);
                    errdefer token.value.deinit(allocator);
                    try list.append(token.value);
                    offset += token.n_bytes;
                }
                return .{
                    .n_bytes = offset + 1,
                    .value = .{ .list = list },
                };
            },
            'd' => {
                var offset: usize = 1;
                var value = BencodeValue{ .dict = std.StringArrayHashMap(BencodeValue).init(allocator) };
                errdefer value.deinit(allocator);
                while (offset < data.len and data[offset] != 'e') {
                    var key_token = try decode(allocator, data[offset..]);
                    offset += key_token.n_bytes;
                    errdefer key_token.value.deinit(allocator);
                    if (key_token.value != .string) {
                        return error.InvalidArgument;
                    }
                    var value_token = try decode(allocator, data[offset..]);
                    offset += value_token.n_bytes;
                    errdefer value_token.value.deinit(allocator);
                    var prev = try value.dict.fetchPut(key_token.value.string, value_token.value);
                    if (prev) |*kv| {
                        allocator.free(kv.key);
                        kv.value.deinit(allocator);
                    }
                }
                return .{ .n_bytes = offset + 1, .value = value };
            },
            else => return error.InvalidArgument,
        }
    }

    pub fn sort(self: *BencodeValue) void {
        switch (self.*) {
            .int, .string => {},
            .list => |l| for (l.items) |v| v.sort(),
            .dict => |d| {
                const S = struct {
                    map: *const std.StringArrayHashMap(BencodeValue),
                    pub fn lessThan(self0: @This(), a_index: usize, b_index: usize) bool {
                        const a_key = self0.map.unmanaged.entries.get(a_index).key;
                        const b_key = self0.map.unmanaged.entries.get(b_index).key;
                        return std.mem.lessThan(u8, a_key, b_key);
                    }
                };
                d.sort(S{ .map = &d });
                var it = d.iterator();
                for (it.next()) |e| e.value_ptr.sort();
            },
        }
    }

    pub fn jsonStringify(
        self: BencodeValue,
        writer: anytype,
    ) !void {
        switch (self) {
            .int => |v| try writer.write(v),
            .string => |v| try writer.write(v),
            .list => |l| try writer.write(l.items),
            .dict => |d| {
                try writer.beginObject();
                var it = d.iterator();
                while (it.next()) |e| {
                    try writer.objectField(e.key_ptr.*);
                    try e.value_ptr.jsonStringify(writer);
                }
                try writer.endObject();
            },
        }
    }

    pub fn has(self: BencodeValue, key: []const u8) bool {
        if (self != .dict) return false;
        return self.dict.contains(key);
    }

    // the key is owned by the Value after this call
    pub fn set(self: *BencodeValue, allocator: std.mem.Allocator, key: []const u8, value: BencodeValue) !void {
        if (self.* != .dict) return error.WrongType;
        const key_dupe = try allocator.dupe(u8, key);
        errdefer allocator.free(key_dupe);
        try self.dict.put(key_dupe, value);
    }

    pub fn get(self: BencodeValue, key: []const u8, comptime field: std.meta.Tag(BencodeValue)) !std.meta.TagPayload(BencodeValue, field) {
        if (self != .dict) return error.NotADictionary;

        const value = self.dict.get(key) orelse return error.KeyNotFound;
        if (value != field) return error.WrongType;

        return switch (field) {
            .int => value.int,
            .string => value.string,
            .list => value.list,
            .dict => value.dict,
        };
    }
};

fn expectEncodedString(expected: []const u8, value: BencodeValue) !void {
    var output = std.ArrayList(u8).init(testing.allocator);
    defer output.deinit();
    try value.encode(output.writer());
    try testing.expectEqualStrings(expected, output.items);
}

test "BencodeValue.decode: string" {
    var token = try BencodeValue.decode(testing.allocator, "4:test");
    defer token.value.deinit(testing.allocator);
    try testing.expectEqualDeep(BencodeToken{ .n_bytes = 6, .value = .{ .string = "test" } }, token);
}

test "BencodeValue.decode: integer" {
    var token = try BencodeValue.decode(testing.allocator, "i123e");
    defer token.value.deinit(testing.allocator);
    try testing.expectEqualDeep(BencodeToken{ .n_bytes = 5, .value = .{ .int = 123 } }, token);
}

test "BencodeValue.decode: list" {
    var token = try BencodeValue.decode(testing.allocator, "l5:helloi52ee");
    defer token.value.deinit(testing.allocator);
    var list = std.ArrayList(BencodeValue).init(testing.allocator);
    defer list.deinit();
    try list.append(.{ .string = "hello" });
    try list.append(.{ .int = 52 });
    try testing.expectEqualDeep(BencodeToken{ .n_bytes = 13, .value = .{ .list = list } }, token);
}

test "BencodeValue.decode: dict" {
    var token = try BencodeValue.decode(testing.allocator, "d3:foo3:bar5:helloi52ee");
    defer token.value.deinit(testing.allocator);
    try testing.expectEqual(23, token.n_bytes);
    try testing.expect(token.value == .dict);
    const dict = token.value.dict;
    try testing.expectEqual(2, dict.count());
    try testing.expectEqualDeep(BencodeValue{ .string = "bar" }, dict.get("foo").?);
    try testing.expectEqualDeep(BencodeValue{ .int = 52 }, dict.get("hello").?);
}
