const std = @import("std");
const stdout = std.io.getStdOut().writer();
const testing = std.testing;
const BencodeValue = @import("./bencode.zig").BencodeValue;
const MetaInfo = @import("./metainfo.zig").MetaInfo;
const PeerParser = @import("./peer.zig").PeerParser;
const PeerMessage = @import("./peer.zig").PeerMessage;
const Handshake = @import("./peer.zig").Handshake;
const ExtensionHandshake = @import("./peer.zig").ExtensionHandshake;
const MagnetLink = @import("./magnet.zig").MagnetLink;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try stdout.print("Usage: your_bittorrent.zig <command> <args>\n", .{});
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "decode")) {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        std.debug.print("Logs from your program will appear here\n", .{});

        // Uncomment this block to pass the first stage
        const encoded = args[2];
        var token = BencodeValue.decode(allocator, encoded) catch |err| {
            std.debug.print("Invalid value: {s}\n", .{@errorName(err)});
            std.process.exit(1);
        };
        defer token.value.deinit(allocator);
        try std.json.stringify(token.value, .{}, stdout);
        try stdout.print("\n", .{});
    }

    if (std.mem.eql(u8, command, "info")) {
        const data = try std.fs.cwd().readFileAlloc(allocator, args[2], std.math.maxInt(usize));
        defer allocator.free(data);
        var meta_info = try MetaInfo.parse(allocator, data);
        defer meta_info.deinit();

        try stdout.print("Tracker URL: {s}\n", .{meta_info.announce});
        try stdout.print("Length: {d}\n", .{meta_info.info.length});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(meta_info.info.hash, .lower)});
        try stdout.print("Piece Length: {d}\n", .{meta_info.info.piece_length});
        try stdout.print("Piece Hashes:\n", .{});
        for (meta_info.info.pieces) |s| try stdout.print("{s}\n", .{std.fmt.bytesToHex(s, .lower)});
    }

    if (std.mem.eql(u8, command, "peers")) {
        var meta_info = try MetaInfo.readFile(allocator, args[2]);
        defer meta_info.deinit();

        const peers = try getTrackerPeerList(allocator, .{
            .announce_url = meta_info.announce,
            .info_hash = &meta_info.info.hash,
            .left = meta_info.info.length,
        });
        defer allocator.free(peers);

        for (peers) |peer| {
            try stdout.print("{}\n", .{peer});
        }
    }

    if (std.mem.eql(u8, command, "handshake")) {
        var meta_info = try MetaInfo.readFile(allocator, args[2]);
        defer meta_info.deinit();

        const addr = try parseAddrArg(args[3]);
        const stream = try std.net.tcpConnectToAddress(.{ .in = addr });
        defer stream.close();

        const hanshake_out = Handshake{
            .infohash = meta_info.info.hash,
            .peer_id = [_]u8{'A'} ** 20,
        };
        try hanshake_out.write(stream.writer());

        const handshake_in = try Handshake.read(stream.reader());
        try stdout.print("Peer ID: {s}\n", .{std.fmt.bytesToHex(handshake_in.peer_id, .lower)});
    }

    if (std.mem.eql(u8, command, "download_piece")) {
        // Read the torrent file to get the tracker URL
        var meta_info = try MetaInfo.readFile(allocator, args[4]);
        defer meta_info.deinit();

        try stdout.print("MetaInfo: pieces={d}, piece_length={d}, length={d}\n", .{
            meta_info.info.pieces.len,
            meta_info.info.piece_length,
            meta_info.info.length,
        });

        // Perform the tracker GET request to get a list of peers
        const peers = try getTrackerPeerList(allocator, .{
            .announce_url = meta_info.announce,
            .info_hash = &meta_info.info.hash,
            .left = meta_info.info.length,
        });
        defer allocator.free(peers);
        if (peers.len == 0) return error.NoPeers;

        // Choose a random peer
        var rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            break :blk seed;
        });
        const peer_idx = rng.random().intRangeLessThan(usize, 0, peers.len);
        const peer = peers[peer_idx];

        // Establish a TCP connection with a peer, and perform a handshake
        const stream = try std.net.tcpConnectToAddress(.{ .in = peer });
        defer stream.close();
        const hanshake_out = Handshake{
            .infohash = meta_info.info.hash,
            .peer_id = [_]u8{'A'} ** 20,
        };
        try hanshake_out.write(stream.writer());
        const handshake_in = try Handshake.read(stream.reader());
        try stdout.print("Peer ID: {s}\n", .{std.fmt.bytesToHex(handshake_in.peer_id, .lower)});

        // Wait for a bitfield message from the peer indicating which pieces it has
        var bitfield_msg = try PeerMessage.read(allocator, stream.reader());
        defer bitfield_msg.deinit(allocator);
        if (bitfield_msg != .bitfield) return error.UnexpectedMessageType;
        try stdout.print("Bitfield: received\n", .{});

        // Send an interested message
        try PeerMessage.write(.interested, stream.writer());
        try stdout.print("Interested: sent\n", .{});

        // Wait until you receive an unchoke message back
        while (true) {
            var msg = try PeerMessage.read(allocator, stream.reader());
            defer msg.deinit(allocator);
            if (msg == .unchoke) break;
            try stdout.print("Waiting for Unchoke: got {s}\n", .{@tagName(msg)});
        }
        try stdout.print("Recieved Unchoke\n", .{});

        // Break the piece into blocks of 16 kiB (16 * 1024 bytes) and send a request message for each block
        const piece_index = try std.fmt.parseInt(usize, args[5], 10);
        var piece = try meta_info.info.piece(allocator, piece_index);
        defer piece.deinit();
        try stdout.print("Piece: index={d}, length={d}\n", .{ piece_index, piece.data.len });

        for (piece.blocks) |block| {
            try PeerMessage.write(.{ .request = .{
                .index = @intCast(piece_index),
                .begin = @intCast(block.begin),
                .length = @intCast(block.length),
            } }, stream.writer());
            try stdout.print("Request: index={d} begin={d} length={d}\n", .{
                piece_index,
                block.begin,
                block.length,
            });

            var msg = try PeerMessage.read(allocator, stream.reader());
            errdefer msg.deinit(allocator);
            if (msg != .piece) return error.UnexpectedMessageType;
            try stdout.print("Piece: index={d} begin={d} length={d}\n", .{
                msg.piece.index,
                msg.piece.begin,
                msg.piece.block.len,
            });

            try piece.add(msg.piece.begin, msg.piece.block);
        }

        // Make sure all the blocks were recieved
        if (!piece.complete()) return error.MissingBlocks;

        // Write the piece out to a file
        try std.fs.cwd().writeFile(args[3], piece.data);
    }

    if (std.mem.eql(u8, command, "download")) {
        // Read the torrent file to get the tracker URL
        var meta_info = try MetaInfo.readFile(allocator, args[4]);
        defer meta_info.deinit();

        try stdout.print("MetaInfo: name={s} pieces={d}, piece_length={d}, length={d}\n", .{
            meta_info.info.name,
            meta_info.info.pieces.len,
            meta_info.info.piece_length,
            meta_info.info.length,
        });

        // Perform the tracker GET request to get a list of peers
        const peers = try getTrackerPeerList(allocator, .{
            .announce_url = meta_info.announce,
            .info_hash = &meta_info.info.hash,
            .left = meta_info.info.length,
        });
        defer allocator.free(peers);
        if (peers.len == 0) return error.NoPeers;

        // Choose a random peer
        var rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            break :blk seed;
        });
        const peer_idx = rng.random().intRangeLessThan(usize, 0, peers.len);
        const peer = peers[peer_idx];

        // Establish a TCP connection with a peer, and perform a handshake
        const stream = try std.net.tcpConnectToAddress(.{ .in = peer });
        defer stream.close();
        const hanshake_out = Handshake{
            .infohash = meta_info.info.hash,
            .peer_id = [_]u8{'A'} ** 20,
        };
        try hanshake_out.write(stream.writer());
        const handshake_in = try Handshake.read(stream.reader());
        try stdout.print("Peer ID: {s}\n", .{std.fmt.bytesToHex(handshake_in.peer_id, .lower)});

        // Wait for a bitfield message from the peer indicating which pieces it has
        var bitfield_msg = try PeerMessage.read(allocator, stream.reader());
        defer bitfield_msg.deinit(allocator);
        if (bitfield_msg != .bitfield) return error.UnexpectedMessageType;
        try stdout.print("Bitfield: received\n", .{});

        // Send an interested message
        try PeerMessage.write(.interested, stream.writer());
        try stdout.print("Interested: sent\n", .{});

        // Wait until you receive an unchoke message back
        while (true) {
            var msg = try PeerMessage.read(allocator, stream.reader());
            defer msg.deinit(allocator);
            if (msg == .unchoke) break;
            try stdout.print("Waiting for Unchoke: got {s}\n", .{@tagName(msg)});
        }
        try stdout.print("Recieved Unchoke\n", .{});

        const outfile = try std.fs.cwd().createFile(args[3], .{});
        defer outfile.close();

        for (meta_info.info.pieces, 0..) |_, index| {
            var piece = try meta_info.info.piece(allocator, index);
            defer piece.deinit();
            try stdout.print("Piece: index={d}, length={d}\n", .{ index, piece.data.len });

            for (piece.blocks) |block| {
                try PeerMessage.write(.{ .request = .{
                    .index = @intCast(index),
                    .begin = @intCast(block.begin),
                    .length = @intCast(block.length),
                } }, stream.writer());
                try stdout.print("Request: index={d} begin={d} length={d}\n", .{
                    index,
                    block.begin,
                    block.length,
                });
            }

            while (!piece.complete()) {
                var msg = try PeerMessage.read(allocator, stream.reader());
                defer msg.deinit(allocator);
                if (msg != .piece) return error.UnexpectedMessageType;
                try stdout.print("Piece: index={d} begin={d} length={d}\n", .{
                    msg.piece.index,
                    msg.piece.begin,
                    msg.piece.block.len,
                });

                try piece.add(msg.piece.begin, msg.piece.block);
            }

            try outfile.writeAll(piece.data);
        }

        try outfile.sync();
    }

    if (std.mem.eql(u8, command, "magnet_parse")) {
        var link = try MagnetLink.parse(allocator, args[2]);
        defer link.deinit();
        const info_hash = try link.getInfoHash();
        try stdout.print("Tracker URL: {s}\n", .{link.tr});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(info_hash, .lower)});
    }

    if (std.mem.eql(u8, command, "magnet_handshake")) {
        var link = try MagnetLink.parse(allocator, args[2]);
        defer link.deinit();
        const info_hash = try link.getInfoHash();
        const peers = try getTrackerPeerList(allocator, .{
            .announce_url = link.tr,
            .info_hash = &info_hash,
            .left = 999,
        });
        defer allocator.free(peers);
        if (peers.len == 0) return error.NoPeers;

        // Choose a random peer
        var rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            break :blk seed;
        });
        const peer_idx = rng.random().intRangeLessThan(usize, 0, peers.len);
        const peer = peers[peer_idx];

        // Establish a TCP connection with a peer, and perform a handshake
        const stream = try std.net.tcpConnectToAddress(.{ .in = peer });
        defer stream.close();
        const hanshake_out = Handshake{
            .infohash = info_hash,
            .peer_id = [_]u8{'A'} ** 20,
            .flags = 1 << 20,
        };

        // Do handshake
        try hanshake_out.write(stream.writer());
        const handshake_in = try Handshake.read(stream.reader());

        // Wait for a bitfield message from the peer indicating which pieces it has
        var bitfield_msg = try PeerMessage.read(allocator, stream.reader());
        defer bitfield_msg.deinit(allocator);
        if (bitfield_msg != .bitfield) return error.UnexpectedMessageType;
        try stdout.print("Bitfield: received\n", .{});

        var flags: [8]u8 = undefined;
        std.mem.writeInt(u64, &flags, handshake_in.flags, .big);

        if (handshake_in.flags & (1 << 20) != 0) {
            // send extension handshake
            var ext = ExtensionHandshake.init(allocator);
            defer ext.deinit();
            try ext.add("ut_metadata", 1);
            try ext.write(stream.writer());

            // Read extension handshake
            var ext_in = try ExtensionHandshake.read(allocator, stream.reader());
            defer ext_in.deinit();
            const ut_metadata_id = ext_in.map.get("ut_metadata") orelse 0;
            try stdout.print("Peer Metadata Extension ID: {d}\n", .{ut_metadata_id});
        }

        try stdout.print("Peer ID: {s}\n", .{std.fmt.bytesToHex(handshake_in.peer_id, .lower)});
    }

    if (std.mem.eql(u8, command, "magnet_info")) {
        var link = try MagnetLink.parse(allocator, args[2]);
        defer link.deinit();
        const info_hash = try link.getInfoHash();
        const peers = try getTrackerPeerList(allocator, .{
            .announce_url = link.tr,
            .info_hash = &info_hash,
            .left = 999,
        });
        defer allocator.free(peers);
        if (peers.len == 0) return error.NoPeers;

        // Choose a random peer
        var rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            break :blk seed;
        });
        const peer_idx = rng.random().intRangeLessThan(usize, 0, peers.len);
        const peer = peers[peer_idx];

        // Establish a TCP connection with a peer, and perform a handshake
        const stream = try std.net.tcpConnectToAddress(.{ .in = peer });
        defer stream.close();
        const hanshake_out = Handshake{
            .infohash = info_hash,
            .peer_id = [_]u8{'A'} ** 20,
            .flags = 1 << 20,
        };

        // Do handshake
        try hanshake_out.write(stream.writer());
        const handshake_in = try Handshake.read(stream.reader());

        // Wait for a bitfield message from the peer indicating which pieces it has
        var bitfield_msg = try PeerMessage.read(allocator, stream.reader());
        defer bitfield_msg.deinit(allocator);
        if (bitfield_msg != .bitfield) return error.UnexpectedMessageType;

        var flags: [8]u8 = undefined;
        std.mem.writeInt(u64, &flags, handshake_in.flags, .big);

        if (handshake_in.flags & (1 << 20) != 0) {
            // send extension handshake
            var ext = ExtensionHandshake.init(allocator);
            defer ext.deinit();
            try ext.add("ut_metadata", 1);
            try ext.write(stream.writer());

            // Read extension handshake
            var ext_in = try ExtensionHandshake.read(allocator, stream.reader());
            defer ext_in.deinit();
            const ut_metadata_id = ext_in.map.get("ut_metadata") orelse 0;
            try stdout.print("Peer Metadata Extension ID: {d}\n", .{ut_metadata_id});

            // Send request
            try MetadataRequest.write(
                .{ .piece = 0, .ut_metadata_id = ut_metadata_id },
                allocator,
                stream.writer(),
            );

            // read the data message
            var data = try MetadataData.read(allocator, stream.reader(), ut_metadata_id);
            defer data.deinit(allocator);

            // decode the piece
            var info = try MetaInfo.Info.parse(allocator, data.data);
            defer info.deinit(allocator);
            try stdout.print("Tracker URL: {s}\n", .{link.tr});
            try stdout.print("Length: {d}\n", .{info.length});
            try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(info.hash, .lower)});
            try stdout.print("Piece Length: {d}\n", .{info.piece_length});
            try stdout.print("Piece Hashes:\n", .{});
            for (info.pieces) |piece| {
                try stdout.print("{s}\n", .{std.fmt.bytesToHex(piece, .lower)});
            }
        }
    }

    // Example:
    // $ ./your_bittorrent.sh magnet_download_piece -o /tmp/test-piece-0 <magnet-link> 0
    if (std.mem.eql(u8, command, "magnet_download_piece")) {
        var link = try MagnetLink.parse(allocator, args[4]);
        defer link.deinit();
        const info_hash = try link.getInfoHash();
        const peers = try getTrackerPeerList(allocator, .{
            .announce_url = link.tr,
            .info_hash = &info_hash,
            .left = 999,
        });
        defer allocator.free(peers);
        if (peers.len == 0) return error.NoPeers;

        // Choose a random peer
        var rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            break :blk seed;
        });
        const peer_idx = rng.random().intRangeLessThan(usize, 0, peers.len);
        const peer = peers[peer_idx];

        // Establish a TCP connection with a peer, and perform a handshake
        const stream = try std.net.tcpConnectToAddress(.{ .in = peer });
        defer stream.close();
        const hanshake_out = Handshake{
            .infohash = info_hash,
            .peer_id = [_]u8{'A'} ** 20,
            .flags = 1 << 20,
        };

        // Do handshake
        try hanshake_out.write(stream.writer());
        const handshake_in = try Handshake.read(stream.reader());

        // Wait for a bitfield message from the peer indicating which pieces it has
        var bitfield_msg = try PeerMessage.read(allocator, stream.reader());
        defer bitfield_msg.deinit(allocator);
        if (bitfield_msg != .bitfield) return error.UnexpectedMessageType;

        var flags: [8]u8 = undefined;
        std.mem.writeInt(u64, &flags, handshake_in.flags, .big);

        if (handshake_in.flags & (1 << 20) == 0) return error.ExtensionNotSupported;
        // send extension handshake
        var ext = ExtensionHandshake.init(allocator);
        defer ext.deinit();
        try ext.add("ut_metadata", 1);
        try ext.write(stream.writer());

        // Read extension handshake
        var ext_in = try ExtensionHandshake.read(allocator, stream.reader());
        defer ext_in.deinit();
        const ut_metadata_id = ext_in.map.get("ut_metadata") orelse 0;
        try stdout.print("Peer Metadata Extension ID: {d}\n", .{ut_metadata_id});

        // Send request
        try MetadataRequest.write(
            .{ .piece = 0, .ut_metadata_id = ut_metadata_id },
            allocator,
            stream.writer(),
        );

        // read the data message
        var data = try MetadataData.read(allocator, stream.reader(), ut_metadata_id);
        defer data.deinit(allocator);

        // decode the piece
        var info = try MetaInfo.Info.parse(allocator, data.data);
        defer info.deinit(allocator);
        try stdout.print("Tracker URL: {s}\n", .{link.tr});
        try stdout.print("Length: {d}\n", .{info.length});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(info.hash, .lower)});
        try stdout.print("Piece Length: {d}\n", .{info.piece_length});
        try stdout.print("Piece Hashes:\n", .{});
        for (info.pieces) |piece| {
            try stdout.print("{s}\n", .{std.fmt.bytesToHex(piece, .lower)});
        }

        // Send an interested message
        try PeerMessage.write(.interested, stream.writer());
        try stdout.print("Interested: sent\n", .{});

        // Wait until you receive an unchoke message back
        while (true) {
            var msg = try PeerMessage.read(allocator, stream.reader());
            defer msg.deinit(allocator);
            if (msg == .unchoke) break;
            try stdout.print("Waiting for Unchoke: got {s}\n", .{@tagName(msg)});
        }
        try stdout.print("Recieved Unchoke\n", .{});

        // Break the piece into blocks of 16 kiB (16 * 1024 bytes) and send a request message for each block
        const piece_index = try std.fmt.parseInt(usize, args[5], 10);
        var piece = try info.piece(allocator, piece_index);
        defer piece.deinit();
        try stdout.print("Piece: index={d}, length={d}\n", .{ piece_index, piece.data.len });

        for (piece.blocks) |block| {
            try PeerMessage.write(.{ .request = .{
                .index = @intCast(piece_index),
                .begin = @intCast(block.begin),
                .length = @intCast(block.length),
            } }, stream.writer());
            try stdout.print("Request: index={d} begin={d} length={d}\n", .{
                piece_index,
                block.begin,
                block.length,
            });

            var msg = try PeerMessage.read(allocator, stream.reader());
            errdefer msg.deinit(allocator);
            if (msg != .piece) return error.UnexpectedMessageType;
            try stdout.print("Piece: index={d} begin={d} length={d}\n", .{
                msg.piece.index,
                msg.piece.begin,
                msg.piece.block.len,
            });

            try piece.add(msg.piece.begin, msg.piece.block);
        }

        // Make sure all the blocks were recieved
        if (!piece.complete()) return error.MissingBlocks;

        // Write the piece out to a file
        try std.fs.cwd().writeFile(args[3], piece.data);
    }

    // Example:
    // $ ./your_bittorrent.sh magnet_download -o /tmp/sample <magnet-link>
    if (std.mem.eql(u8, command, "magnet_download")) {
        var link = try MagnetLink.parse(allocator, args[4]);
        defer link.deinit();
        const info_hash = try link.getInfoHash();
        const peers = try getTrackerPeerList(allocator, .{
            .announce_url = link.tr,
            .info_hash = &info_hash,
            .left = 999,
        });
        defer allocator.free(peers);
        if (peers.len == 0) return error.NoPeers;

        // Choose a random peer
        var rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            try std.posix.getrandom(std.mem.asBytes(&seed));
            break :blk seed;
        });
        const peer_idx = rng.random().intRangeLessThan(usize, 0, peers.len);
        const peer = peers[peer_idx];

        // Establish a TCP connection with a peer, and perform a handshake
        const stream = try std.net.tcpConnectToAddress(.{ .in = peer });
        defer stream.close();
        const hanshake_out = Handshake{
            .infohash = info_hash,
            .peer_id = [_]u8{'A'} ** 20,
            .flags = 1 << 20,
        };

        // Do handshake
        try hanshake_out.write(stream.writer());
        const handshake_in = try Handshake.read(stream.reader());

        // Wait for a bitfield message from the peer indicating which pieces it has
        var bitfield_msg = try PeerMessage.read(allocator, stream.reader());
        defer bitfield_msg.deinit(allocator);
        if (bitfield_msg != .bitfield) return error.UnexpectedMessageType;

        var flags: [8]u8 = undefined;
        std.mem.writeInt(u64, &flags, handshake_in.flags, .big);

        if (handshake_in.flags & (1 << 20) == 0) return error.ExtensionNotSupported;
        // send extension handshake
        var ext = ExtensionHandshake.init(allocator);
        defer ext.deinit();
        try ext.add("ut_metadata", 1);
        try ext.write(stream.writer());

        // Read extension handshake
        var ext_in = try ExtensionHandshake.read(allocator, stream.reader());
        defer ext_in.deinit();
        const ut_metadata_id = ext_in.map.get("ut_metadata") orelse 0;
        try stdout.print("Peer Metadata Extension ID: {d}\n", .{ut_metadata_id});

        // Send request
        try MetadataRequest.write(
            .{ .piece = 0, .ut_metadata_id = ut_metadata_id },
            allocator,
            stream.writer(),
        );

        // read the data message
        var data = try MetadataData.read(allocator, stream.reader(), ut_metadata_id);
        defer data.deinit(allocator);

        // decode the piece
        var info = try MetaInfo.Info.parse(allocator, data.data);
        defer info.deinit(allocator);
        try stdout.print("Tracker URL: {s}\n", .{link.tr});
        try stdout.print("Length: {d}\n", .{info.length});
        try stdout.print("Info Hash: {s}\n", .{std.fmt.bytesToHex(info.hash, .lower)});
        try stdout.print("Piece Length: {d}\n", .{info.piece_length});
        try stdout.print("Piece Hashes:\n", .{});
        for (info.pieces) |piece| {
            try stdout.print("{s}\n", .{std.fmt.bytesToHex(piece, .lower)});
        }

        // Send an interested message
        try PeerMessage.write(.interested, stream.writer());
        try stdout.print("Interested: sent\n", .{});

        // Wait until you receive an unchoke message back
        while (true) {
            var msg = try PeerMessage.read(allocator, stream.reader());
            defer msg.deinit(allocator);
            if (msg == .unchoke) break;
            try stdout.print("Waiting for Unchoke: got {s}\n", .{@tagName(msg)});
        }
        try stdout.print("Recieved Unchoke\n", .{});

        const outfile = try std.fs.cwd().createFile(args[3], .{});
        defer outfile.close();

        for (info.pieces, 0..) |_, index| {
            var piece = try info.piece(allocator, index);
            defer piece.deinit();
            try stdout.print("Piece: index={d}, length={d}\n", .{ index, piece.data.len });

            for (piece.blocks) |block| {
                try PeerMessage.write(.{ .request = .{
                    .index = @intCast(index),
                    .begin = @intCast(block.begin),
                    .length = @intCast(block.length),
                } }, stream.writer());
                try stdout.print("Request: index={d} begin={d} length={d}\n", .{
                    index,
                    block.begin,
                    block.length,
                });
            }

            while (!piece.complete()) {
                var msg = try PeerMessage.read(allocator, stream.reader());
                defer msg.deinit(allocator);
                if (msg != .piece) return error.UnexpectedMessageType;
                try stdout.print("Piece: index={d} begin={d} length={d}\n", .{
                    msg.piece.index,
                    msg.piece.begin,
                    msg.piece.block.len,
                });

                try piece.add(msg.piece.begin, msg.piece.block);
            }

            try outfile.writeAll(piece.data);
        }

        try outfile.sync();
    }
}

const MetadataData = struct {
    piece: usize,
    total_size: u64,
    data: []const u8,
    ut_metadata_id: u64,

    pub fn read(allocator: std.mem.Allocator, reader: anytype, ut_metadata_id: u64) !MetadataData {
        var msg = try PeerMessage.read(allocator, reader);
        defer msg.deinit(allocator);
        if (msg != .extension) return error.UnexpectedMessageType;
        // TODO: re-enable this
        // if (msg.extension.id != ut_metadata_id) {
        //     std.debug.print("ut_metadata_id mismatch: got={d}, want={d}\n", .{ msg.extension.id, ut_metadata_id });
        //     return error.UnexpectedMessageType;
        // }
        const msg_type = try msg.extension.value.get("msg_type", .int);
        if (msg_type != 1) return error.UnexpectedMessageType;
        const piece = try msg.extension.value.get("piece", .int);
        const total_size = try msg.extension.value.get("total_size", .int);
        const data = try allocator.dupe(u8, msg.extension.data);
        errdefer allocator.free(data);
        return .{
            .piece = @intCast(piece),
            .total_size = @intCast(total_size),
            .data = data,
            .ut_metadata_id = ut_metadata_id,
        };
    }

    pub fn deinit(self: *MetadataData, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

const MetadataRequest = struct {
    piece: usize,
    ut_metadata_id: u64,

    pub fn write(self: MetadataRequest, allocator: std.mem.Allocator, writer: anytype) !void {
        var dict = BencodeValue.initDict(allocator);
        defer dict.deinit(allocator);
        try dict.set(allocator, "msg_type", BencodeValue{ .int = 0 });
        try dict.set(allocator, "piece", BencodeValue{ .int = @intCast(self.piece) });
        try PeerMessage.write(.{
            .extension = .{
                .id = @intCast(self.ut_metadata_id),
                .value = dict,
                .data = &[_]u8{},
            },
        }, writer);
    }
};

const TrackerPeerOptions = struct {
    announce_url: []const u8,
    info_hash: []const u8,
    left: ?i64 = null,
};

pub fn getTrackerPeerList(allocator: std.mem.Allocator, options: TrackerPeerOptions) ![]std.net.Ip4Address {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const url = try buildTrackerPeerUrl(allocator, options);
    defer allocator.free(url);

    const uri = try std.Uri.parse(url);
    var header_buf: [4096]u8 = undefined;
    var req = try client.open(.GET, uri, .{ .server_header_buffer = &header_buf });
    defer req.deinit();

    try req.send();
    try req.finish();
    try req.wait();

    if (req.response.status != std.http.Status.ok) return error.UnexpectedStatusCode;

    var reader = req.reader();
    const body = try reader.readAllAlloc(allocator, 4 << 20);
    defer allocator.free(body);

    var res_token = try BencodeValue.decode(allocator, body);
    defer res_token.value.deinit(allocator);

    // check for failure
    if (res_token.value.has("failure reason")) {
        const reason = try res_token.value.get("failure reason", .string);
        try stdout.print("failure reason: {s}\n", .{reason});
        return error.TrackerRequestFailure;
    }

    // const interval = try res_token.value.get("interval", .int);
    const peers_raw = res_token.value.get("peers", .string) catch |err| {
        if (res_token.value != .dict) return err;
        var it = res_token.value.dict.iterator();
        while (it.next()) |e| {
            try stdout.print("res_token.value: key: {s}\n", .{e.key_ptr.*});
        }
        return err;
    };
    return PeerParser.parse(allocator, peers_raw);
}

pub fn buildTrackerPeerUrl(allocator: std.mem.Allocator, options: TrackerPeerOptions) ![]const u8 {
    var url = std.ArrayList(u8).init(allocator);
    defer url.deinit();
    const writer = url.writer();
    try std.fmt.format(writer, "{s}", .{options.announce_url});
    try std.fmt.format(writer, "?info_hash={query}", .{std.Uri.Component{ .raw = options.info_hash }});
    try std.fmt.format(writer, "&peer_id={query}", .{std.Uri.Component{ .raw = "AAAAAAAAAAAAAAAAAAAA" }});
    try std.fmt.format(writer, "&port=6881", .{});
    try std.fmt.format(writer, "&uploaded=0", .{});
    try std.fmt.format(writer, "&downloaded=0", .{});
    if (options.left) |left| {
        try std.fmt.format(writer, "&left={d}", .{left});
    }
    try std.fmt.format(writer, "&compact=1", .{});
    return url.toOwnedSlice();
}

pub fn parseAddrArg(arg: []const u8) !std.net.Ip4Address {
    const colon = std.mem.indexOfScalar(u8, arg, ':') orelse return error.InvalidAddr;
    const port = try std.fmt.parseInt(u16, arg[colon + 1 ..], 10);
    return std.net.Ip4Address.parse(arg[0..colon], port);
}

test "buildTrackerPeerUrl: magnet" {
    var magnet = try MagnetLink.parse(
        testing.allocator,
        "magnet:?xt=urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165&dn=magnet1.gif&tr=http%3A%2F%2Fbittorrent-test-tracker.codecrafters.io%2Fannounce",
    );
    defer magnet.deinit();
    const info_hash = try magnet.getInfoHash();
    const url = try buildTrackerPeerUrl(testing.allocator, .{
        .announce_url = magnet.tr,
        .info_hash = &info_hash,
    });
    defer testing.allocator.free(url);
    std.debug.print("Tracker URL: {s}\n", .{url});
}
