const std = @import("std");
const testing = std.testing;
const Piece = @import("./piece.zig").Piece;
const BencodeValue = @import("./bencode.zig").BencodeValue;

pub const MetaInfo = struct {
    pub const Hash = [std.crypto.hash.Sha1.digest_length]u8;

    pub const Info = struct {
        length: i64,
        name: []const u8,
        piece_length: i64,
        pieces: []Hash,
        hash: Hash,

        pub fn piece(self: Info, allocator: std.mem.Allocator, index: usize) !Piece {
            const length = self.pieceLength(index);
            return Piece.init(allocator, length);
        }

        pub fn pieceLength(self: Info, index: usize) usize {
            if (index < 0 or index >= self.pieces.len) return 0;
            const file_len: usize = @intCast(self.length);
            const piece_len: usize = @intCast(self.piece_length);
            if (piece_len * (index + 1) > file_len) {
                return @mod(file_len, piece_len);
            }
            return piece_len;
        }

        pub fn parse(allocator: std.mem.Allocator, data: []const u8) !Info {
            var token = try BencodeValue.decode(allocator, data);
            defer token.value.deinit(allocator);
            if (token.value != .dict) return error.InvalidMetaInfo;
            const value = token.value;
            var info = Info{
                .length = 0,
                .name = "",
                .piece_length = 0,
                .pieces = &[_]Hash{},
                .hash = undefined,
            };
            errdefer info.deinit(allocator);
            info.length = try value.get("length", .int);
            info.name = try allocator.dupe(u8, try value.get("name", .string));
            info.piece_length = try value.get("piece length", .int);
            // parse the piece hashes
            const piece_length: usize = 20;
            const pieces_string = try value.get("pieces", .string);
            if (pieces_string.len % piece_length != 0) {
                return error.InvalidMetaInfo;
            }
            var pieces = std.ArrayList(Hash).init(allocator);
            defer pieces.deinit();
            var pieces_offset: usize = 0;
            while (pieces_offset < pieces_string.len) {
                var hash: Hash = undefined;
                std.mem.copyForwards(u8, &hash, pieces_string[pieces_offset .. pieces_offset + piece_length]);
                try pieces.append(hash);
                pieces_offset += piece_length;
            }
            info.pieces = try pieces.toOwnedSlice();
            // compute the meta info hash
            std.crypto.hash.Sha1.hash(
                data[0..token.n_bytes],
                &info.hash,
                .{},
            );
            return info;
        }

        pub fn deinit(self: *Info, allocator: std.mem.Allocator) void {
            allocator.free(self.name);
            allocator.free(self.pieces);
        }
    };

    allocator: std.mem.Allocator,
    announce: []const u8,
    info: Info,
    test "pieceLength" {
        var pieces = [_]Hash{[1]u8{0} ** 20} ** 10;
        const meta_info = MetaInfo{
            .allocator = testing.allocator,
            .announce = "",
            .info = .{
                .length = 2549700,
                .name = "",
                .piece_length = 262144,
                .pieces = &pieces,
                .hash = undefined,
            },
        };
        try testing.expectEqual(190404, meta_info.ino.pieceLength(9));
    }

    pub fn deinit(self: *MetaInfo) void {
        self.allocator.free(self.announce);
        self.allocator.free(self.info.name);
        self.allocator.free(self.info.pieces);
    }

    pub fn parse(allocator: std.mem.Allocator, data: []const u8) !MetaInfo {
        var token = try BencodeValue.decode(allocator, data);
        defer token.value.deinit(allocator);
        if (token.n_bytes != data.len) {
            return error.InvalidMetaInfo;
        }
        if (token.value != .dict) {
            return error.InvalidMetaInfo;
        }
        const announce = try token.value.get("announce", .string);
        var meta_info = MetaInfo{
            .allocator = allocator,
            .announce = "",
            .info = .{
                .length = 0,
                .name = "",
                .piece_length = 0,
                .pieces = &[_]Hash{},
                .hash = undefined,
            },
        };
        errdefer meta_info.deinit();
        meta_info.announce = try allocator.dupe(u8, announce);
        // parse the info
        const info_offset = BencodeValue.find(data, "info").?;
        meta_info.info = try Info.parse(allocator, data[info_offset..]);
        return meta_info;
    }

    pub fn readFile(allocator: std.mem.Allocator, name: []const u8) !MetaInfo {
        const data = try std.fs.cwd().readFileAlloc(allocator, name, std.math.maxInt(usize));
        defer allocator.free(data);
        return MetaInfo.parse(allocator, data);
    }
};

test "MetaInfo.parse" {
    const meta_info_data = [_]u8{
        0x64, 0x38, 0x3a, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x35,
        0x35, 0x3a, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x62, 0x69, 0x74,
        0x74, 0x6f, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x65, 0x73, 0x74,
        0x2d, 0x74, 0x72, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x64,
        0x65, 0x63, 0x72, 0x61, 0x66, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6f,
        0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x75, 0x6e, 0x63, 0x65, 0x31, 0x30, 0x3a,
        0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x20, 0x62, 0x79, 0x31, 0x33,
        0x3a, 0x6d, 0x6b, 0x74, 0x6f, 0x72, 0x72, 0x65, 0x6e, 0x74, 0x20, 0x31,
        0x2e, 0x31, 0x34, 0x3a, 0x69, 0x6e, 0x66, 0x6f, 0x64, 0x36, 0x3a, 0x6c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x69, 0x39, 0x32, 0x30, 0x36, 0x33, 0x65,
        0x34, 0x3a, 0x6e, 0x61, 0x6d, 0x65, 0x31, 0x30, 0x3a, 0x73, 0x61, 0x6d,
        0x70, 0x6c, 0x65, 0x2e, 0x74, 0x78, 0x74, 0x31, 0x32, 0x3a, 0x70, 0x69,
        0x65, 0x63, 0x65, 0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x69, 0x33,
        0x32, 0x37, 0x36, 0x38, 0x65, 0x36, 0x3a, 0x70, 0x69, 0x65, 0x63, 0x65,
        0x73, 0x36, 0x30, 0x3a, 0xe8, 0x76, 0xf6, 0x7a, 0x2a, 0x88, 0x86, 0xe8,
        0xf3, 0x6b, 0x13, 0x67, 0x26, 0xc3, 0x0f, 0xa2, 0x97, 0x03, 0x02, 0x2d,
        0x6e, 0x22, 0x75, 0xe6, 0x04, 0xa0, 0x76, 0x66, 0x56, 0x73, 0x6e, 0x81,
        0xff, 0x10, 0xb5, 0x52, 0x04, 0xad, 0x8d, 0x35, 0xf0, 0x0d, 0x93, 0x7a,
        0x02, 0x13, 0xdf, 0x19, 0x82, 0xbc, 0x8d, 0x09, 0x72, 0x27, 0xad, 0x9e,
        0x90, 0x9a, 0xcc, 0x17, 0x65, 0x65,
    };
    var meta_info = try MetaInfo.parse(testing.allocator, &meta_info_data);
    defer meta_info.deinit();
    try testing.expectEqualStrings("http://bittorrent-test-tracker.codecrafters.io/announce", meta_info.announce);
    try testing.expectEqual(92063, meta_info.info.length);
    try testing.expectEqualStrings("sample.txt", meta_info.info.name);
    try testing.expectEqual(32768, meta_info.info.piece_length);

    const info_hash = std.fmt.bytesToHex(meta_info.info.hash, .lower);
    try testing.expectEqualStrings("d69f91e6b2ae4c542468d1073a71d4ea13879a7f", &info_hash);
}
