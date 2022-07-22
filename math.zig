const print = std.debug.print;
const std = @import("std");

export fn shannon_entropy(data : [*]u8, data_len: u32) f64 {
    var counts = [_]f32{0} ** 256;
    for (data[0..data_len]) |byte| {
        counts[byte] += 1;
    }
    var ent: f64 = 0.0;

    for (counts) |c| {
        if (c == 0) {
            continue;
        }
        print("Count: {d:.1}", .{c});
        const p = c / @intToFloat(f64, data_len);
        ent -= p * std.math.log2(p);
    }
    return ent;
}
