#![no_std]
#![no_main]

use redbpf_macros::{map, program, xdp};
use redbpf_probes::bindings::*;
use redbpf_probes::xdp::{PerfMap, Transport, XdpAction, XdpContext, MapData};

use bpf_examples::trace_http::RequestInfo;

program!(0xFFFFFFFE, "GPL");

#[map("requests")]
static mut requests: PerfMap<RequestInfo> = PerfMap::with_max_entries(1024);

#[xdp]
pub extern "C" fn trace_http(ctx: XdpContext) -> XdpAction {
    let (ip, transport, data) = match (ctx.ip(), ctx.transport(), ctx.data()) {
        (Some(ip), Some(t @ Transport::TCP(_)), Some(data)) => (unsafe { *ip }, t, data),
        _ => return XdpAction::Pass,
    };

    let buff: [u8; 8] = match data.read() {
        Some(b) => b,
        None => return XdpAction::Pass,
    };

    if &buff[..4] != b"GET "
        && &buff[..4] != b"HEAD"
        && &buff[..4] != b"PUT "
        && &buff[..4] != b"POST"
        && &buff[..6] != b"DELETE" {
        return XdpAction::Pass;
    }

    let info = RequestInfo {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest(),
    };

    unsafe {
        requests.insert(
            &ctx,
            MapData::with_payload(info, data.offset() as u32, data.len() as u32),
        )
    };

    XdpAction::Pass
}
