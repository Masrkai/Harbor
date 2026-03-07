use pnet::datalink;

pub fn get_cidr(interface_name: &str) -> Option<String> {
    let interfaces = datalink::interfaces();
    let iface = interfaces.iter().find(|i| i.name == interface_name)?;

    iface.ips.iter().find_map(|ip| match ip {
        pnet::ipnetwork::IpNetwork::V4(net) => Some(format!("{}/{}", net.network(), net.prefix())),
        _ => None,
    })
}
