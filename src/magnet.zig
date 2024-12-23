const std = @import("std");
const testing = std.testing;

pub const MagnetLink = struct {
    xt: []const u8,
    dn: []const u8,
    tr: []const u8,
    allocator: std.mem.Allocator,

    pub fn parse(allocator: std.mem.Allocator, url: []const u8) !MagnetLink {
        const prefix = "magnet:?";
        if (!std.mem.startsWith(u8, url, prefix)) return error.InvalidMagnetLink;
        var query = url[prefix.len..];

        var link = MagnetLink{
            .xt = "",
            .dn = "",
            .tr = "",
            .allocator = allocator,
        };
        errdefer link.deinit();

        while (true) {
            const end = std.mem.indexOf(u8, query, "&") orelse query.len;
            const pair = query[0..end];
            const eq = std.mem.indexOf(u8, pair, "=") orelse return error.InvalidMagnetLink;
            const key = pair[0..eq];
            const value = pair[eq + 1 ..];
            if (std.mem.eql(u8, key, "xt")) {
                link.xt = try dupeAndDecode(allocator, value);
            }
            if (std.mem.eql(u8, key, "dn")) {
                link.dn = try dupeAndDecode(allocator, value);
            }
            if (std.mem.eql(u8, key, "tr")) {
                link.tr = try dupeAndDecode(allocator, value);
            }
            if (end >= query.len) break;
            query = query[end + 1 ..];
        }

        return link;
    }

    pub fn getInfoHash(self: MagnetLink) ![20]u8 {
        const prefix = "urn:btih:";
        if (!std.mem.startsWith(u8, self.xt, prefix)) {
            return error.InvalidMagnetXT;
        }
        const hex = self.xt[prefix.len..];
        if (hex.len != 40) return error.InvalidMagnetTX;
        var hash = [_]u8{0} ** 20;
        _ = try std.fmt.hexToBytes(&hash, hex);
        return hash;
    }

    fn dupeAndDecode(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
        const dupe = try allocator.dupe(u8, value);
        defer allocator.free(dupe);
        const decoded = std.Uri.percentDecodeInPlace(dupe);
        return try allocator.dupe(u8, decoded);
    }

    pub fn deinit(self: *MagnetLink) void {
        self.allocator.free(self.xt);
        self.allocator.free(self.dn);
        self.allocator.free(self.tr);
    }
};

test "MagnetLink.parse: example" {
    var magnet = try MagnetLink.parse(
        testing.allocator,
        "magnet:?xt=urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165&dn=magnet1.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce",
    );
    defer magnet.deinit();
    try testing.expectEqualStrings("urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165", magnet.xt);
    try testing.expectEqualStrings("magnet1.gif", magnet.dn);
    try testing.expectEqualStrings("http://bittorrent-test-tracker.codecrafters.io/announce", magnet.tr);
}
