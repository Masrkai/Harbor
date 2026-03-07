# 1. Remove the stale tc qdiscs that didn't get cleaned up
sudo tc qdisc del dev eth0 root 2>/dev/null
sudo tc qdisc del dev eth0 ingress 2>/dev/null
sudo tc qdisc del dev ifb0 root 2>/dev/null
sudo ip link set ifb0 down 2>/dev/null
sudo ip link del ifb0 2>/dev/null   # ← this is what you're missing

# 2. Restore rp_filter to its original value (was 2 on your system)
sudo sysctl -w net.ipv4.conf.all.rp_filter=2
sudo sysctl -w net.ipv4.conf.eth0.rp_filter=2

# 3. Restore ip_forward to off (it was 1 before, but that was already the case
#    on your machine — leave it as-is if you use libvirt/VMs)
# sudo sysctl -w net.ipv4.ip_forward=0

# 4. Re-enable send_redirects
sudo sysctl -w net.ipv4.conf.all.send_redirects=1
sudo sysctl -w net.ipv4.conf.eth0.send_redirects=1