const std = @import("std");
const testing = std.testing;

pub const Piece = struct {
    const Block = struct {
        begin: usize,
        length: usize,
        recieved: bool,
    };

    allocator: std.mem.Allocator,
    data: []u8,
    blocks: []Block,

    pub fn init(allocator: std.mem.Allocator, length: usize) !Piece {
        const data = try allocator.alloc(u8, length);
        errdefer allocator.free(data);

        var blocks = std.ArrayList(Block).init(allocator);
        defer blocks.deinit();

        var index: u32 = 0;
        const max_block_len = 16 << 10;
        while (true) : (index += 1) {
            const begin = index * max_block_len;
            const block_len = @min(max_block_len, length - begin);
            if (block_len == 0) break;
            try blocks.append(.{
                .begin = begin,
                .length = block_len,
                .recieved = false,
            });
            if (block_len < max_block_len) break;
        }

        return .{
            .allocator = allocator,
            .data = data,
            .blocks = try blocks.toOwnedSlice(),
        };
    }

    pub fn deinit(self: *Piece) void {
        self.allocator.free(self.data);
        self.allocator.free(self.blocks);
    }

    pub fn complete(self: Piece) bool {
        for (self.blocks) |b| if (!b.recieved) return false;
        return true;
    }

    pub fn add(self: *Piece, begin: usize, block: []const u8) !void {
        var found = false;
        for (self.blocks) |*b| {
            if (b.begin == begin and b.length == block.len) {
                b.recieved = true;
                found = true;
                break;
            }
        }
        if (!found) return error.InvalidBlock;
        std.mem.copyForwards(u8, self.data[begin..], block);
    }
};

test "Piece.init: one byte" {
    var piece = try Piece.init(testing.allocator, 1);
    defer piece.deinit();
    try testing.expectEqual(1, piece.blocks.len);
    try testing.expectEqual(1, piece.data.len);
    try testing.expectEqualDeep(Piece.Block{
        .begin = 0,
        .length = 1,
        .recieved = false,
    }, piece.blocks[0]);
}

test "Piece.init: from example" {
    var piece = try Piece.init(testing.allocator, 190404);
    defer piece.deinit();
    // TODO: more of the test
}
