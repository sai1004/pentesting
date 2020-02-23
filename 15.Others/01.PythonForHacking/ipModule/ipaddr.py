import ipaddress

ip = ipaddress.IPv4Address('192.168.29.1')

# Now this ip object represent a single IP address, we can check whether it is a global IP address (not private)
#  and whether it is a link local:

print("Is Global:", ip.is_global)

print("Is Link-Local:", ip.is_link_local)


# next ip address
print(ip + 1)

# previous ip address
print(ip - 1)


# initialize an IPv4 Network
network = ipaddress.IPv4Network("192.168.29.0/24")

print('Network Mask:', network.netmask)

# get the broadcast address
print("Broadcast address:", network.broadcast_address)

# print the number of IP addresses under this network
print("Number of hosts under", str(network), ":", network.num_addresses)

# iterate over all the hosts under this network
print("Hosts under", str(network), ":")
for host in network.hosts():
    print(host)

# iterate over the subnets of this network
print("Subnets:")
for subnet in network.subnets(prefixlen_diff=2):
    print(subnet)

# get the supernet of this network
print("Supernet:", network.supernet(prefixlen_diff=1))

# tell if this network is under (or overlaps) 192.168.0.0/16
print("Overlaps 192.168.0.0/16:",
      network.overlaps(ipaddress.IPv4Network("192.168.0.0/16")))
