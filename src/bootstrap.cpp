#include "bootstrap.h"

#include "xtea.h"

namespace mwdec {

BootstrapResult run_bootstrap(Image& im, const BootstrapProfile& p, bool apply) {
    BootstrapResult r;
    if (!im.in_bounds(p.key_rva, 16) || !im.in_bounds(p.iv_rva, 8) ||
        !im.in_bounds(p.ranges_rva, 2))
        throw std::runtime_error("bootstrap profile points outside the image");

    // Key, IV and range list are all read before anything is modified: none
    // of them lies inside a range, but this keeps that from mattering.
    for (int i = 0; i < 4; ++i) r.key[i] = im.rd<uint32_t>(p.key_rva + 4 * i);
    r.iv[0] = im.rd<uint32_t>(p.iv_rva);
    r.iv[1] = im.rd<uint32_t>(p.iv_rva + 4);
    r.list = decode_ranges(im.mem.data() + p.ranges_rva, im.mem.size() - p.ranges_rva);

    for (const Range& g : r.list.ranges)
        if (!im.in_bounds(g.rva, g.size))
            throw std::runtime_error("bootstrap range list leaves the image");
    if (!apply) return r;

    // One keystream runs through every range in list order; a range does
    // not restart it and does not realign it to a block boundary.
    XteaOfb ks(r.key, r.iv[0], r.iv[1], p.rounds, p.delta);
    for (const Range& g : r.list.ranges) ks.apply(im.mem.data() + g.rva, g.size);
    r.blocks = ks.blocks();
    r.final_state[0] = ks.state0();
    r.final_state[1] = ks.state1();
    return r;
}

}  // namespace mwdec
