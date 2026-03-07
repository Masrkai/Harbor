echo "=== 1. Routing table ==="
ip route show
echo ""

echo "=== 2. ARP cache ==="
ip neigh show
echo ""

echo "=== 3. tc state ==="
echo "== Generally"
tc qdisc show
echo "-- eth0 --"
tc qdisc show dev eth0
echo "-- ifb0 --"
tc qdisc show dev ifb0
echo ""

echo "=== 4. Kernel parameters ==="
echo "ip_forward:"
cat /proc/sys/net/ipv4/ip_forward
echo "rp_filter:"
cat /proc/sys/net/ipv4/conf/all/rp_filter
echo ""

echo "=== 5. rpfilter chain ==="
sudo nft list chain inet nixos-fw rpfilter