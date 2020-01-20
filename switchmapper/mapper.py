from concurrent.futures import ThreadPoolExecutor as PoolExecutor
from typing import List, Set, Dict, Union, Tuple, Iterable
from collections import defaultdict
import sys, pprint, json, time, argparse, socket
from functools import partial
from itertools import chain

import pysnmp.hlapi as hlapi
import pysnmp.proto.rfc1902 as rfc1902


def snmp_walk(host, oid, format='str', strip_prefix=True, community='public'):
    res = []
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in hlapi.nextCmd(hlapi.SnmpEngine(),
                              hlapi.CommunityData(community),
                              hlapi.UdpTransportTarget((host, 161), timeout=4.0, retries=3),
                              hlapi.ContextData(),
                              hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
                              lookupMib=False,
                              lexicographicMode=False):
        if errorIndication:
            raise ConnectionError(f'SNMP error: "{str(errorIndication)}". Status={str(errorStatus)}')
        elif errorStatus:
            raise ConnectionError('errorStatus: %s at %s' % (errorStatus.prettyPrint(),
                                                             errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for x in varBinds:
                k, v = x
                if strip_prefix:
                    k = str(k)[len(str(oid))+1:]
                if isinstance(v, rfc1902.Integer):
                    res.append((str(k), int(v)))
                else:
                    if format == 'numbers':
                        res.append((str(k), v.asNumbers()))
                    elif format == 'hex':
                        res.append((str(k), v.asOctets().hex()))
                    elif format == 'raw':
                        res.append((str(k), v))
                    elif format == 'bin':
                        res.append((str(k), v.asOctets()))
                    elif format == 'int':
                        res.append((str(k), int(v)))
                    elif format == 'preview':
                        res.append((str(k), str(v)))
                    elif format == 'any':
                        try:
                            res.append((str(k), v.asOctets().decode('utf-8')))
                        except UnicodeDecodeError:
                            res.append((str(k), '0x'+v.asOctets().hex()))
                    elif format == 'str':
                        res.append((str(k), v.asOctets().decode(v.encoding)))
                    else:
                        assert False, "Unknown format for walk()."
    res = {a: b for a, b in res}
    return res


def split_numbers(oid):
    return [int(x) for x in oid.split('.')]


def read_ipv4_from_oid_tail(oid, with_len=True):
    parts = [int(x) for x in oid.split('.')]
    if with_len:
        assert(parts[-5] == 4)  # number of elements
    return '.'.join([str(x) for x in parts[-4:]])


class HashableBase:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
    def __repr__(self):
        return pprint.pformat(self.as_dict(), width=120, compact=True)
    def as_dict(self):
        res = dict(self.__dict__)
        res['__type__'] = self.__class__.__name__
        return res
    def __hash__(self):
        return hash(self.__repr__())
    def __eq__(self, other):
        return self.__repr__() == other.__repr__()


class Port(HashableBase):
    name: str
    interlink: bool
    speed: int  # in Mbps
    local_mac: int
    remote_macs: List[str]
    remote_ips: List[str]

class NeighborInfo(HashableBase):
    name: str
    chassis_id: str
    is_bridge: bool
    macs: List[str]
    ips: List[str]
    in_ports: List[int]

class Bridge(HashableBase):
    chassis_id: str
    ip_addresses: List[str]
    name: str
    desc: str
    neighbors: List[Union[str, NeighborInfo]]
    ports: Dict[int, Port]

    def as_dict(self):
        res = HashableBase.as_dict(self)
        res['ports'] = {k: v.as_dict() for k, v in res['ports'].items()}
        res['neighbors'] = [x.as_dict() for x in res['neighbors']]
        return res



def process_hosts(root_bridge_ips: Iterable[str], community: str,
                  do_recurse=False, all_ports=False, resolve_hostnames=True) -> \
        Tuple[Dict[str, Bridge], Dict[str, str], Dict[str, List[str]], Dict[str, str], str]:
    """
    Recursively query LLDP infos through SNMP from 'root_bridge_ips' and their neighbors.

    :param community: SNMP Community to use for connections
    :param do_recurse: Recurse to neighboring bridge devices?
    :param all_ports: Show all ports, not just active ones?
    :param resolve_hostnames: Resolve hostnames for IP addresses? (slow, albeit parallelized process)
    :param root_bridge_ips: List of IP addresses to hosts that recursion should start from
    :return: (List of bridges, ARP table, Reverse ARP table, IP->Hostname, Results as JSON)
    """
    ips_to_visit = set(list(root_bridge_ips))
    visited_chassis_ids = set()
    visited_ips = set()

    bridges: Dict[str, Bridge] = {}
    all_bridge_macs = set()
    arp = {}

    walk = partial(snmp_walk, community=community)

    while ips_to_visit:
        host = ips_to_visit.pop()
        if host in visited_ips:
            continue
        visited_ips.add(host)

        print("VISITING", host, file=sys.stderr)

        # Skip if chassis ID not found or has already been seen
        try:
            lldpLocChassisId = walk(host, '1.0.8802.1.1.2.1.3.2', 'hex').values()
        except ConnectionError as e:
            print(str(e) + f" -- skipping {host}!", file=sys.stderr)
            continue

        if not lldpLocChassisId:
            print(f"Got no ChassisId from {host} -- missing LLDP support?",  file=sys.stderr)
            continue
        lldpLocChassisId = tuple(lldpLocChassisId)[0]
        if lldpLocChassisId in visited_chassis_ids:
            continue
        visited_chassis_ids.add(lldpLocChassisId)

        all_bridge_macs.add(lldpLocChassisId)  # chassis id looks like a MAC and some switches use it for all their ports

        print(" - Getting local info...", file=sys.stderr)

        # Check that it's a bridge
        lldpLocSysCapSupported = int(tuple(walk(host, '1.0.8802.1.1.2.1.3.5', 'hex').values())[-1], 16)
        is_bridge = (lldpLocSysCapSupported & 32) != 0
        if not is_bridge:
            print(f"Host {host} does not announce Bridge type LLDP capability. Skipping.",  file=sys.stderr)
            continue

        dot1dTpFdbPort_to_portnum = {int(k): v for (k, v) in walk(host, '1.3.6.1.2.1.17.1.4.1.2', 'int').items()}

        # Find local management IP addresses (if supported)
        local_ips = set()
        lldpLocManAddrIfId = walk(host, '1.0.8802.1.1.2.1.3.8.1.5', 'preview')  # local man addresses
        for oid, port_id in lldpLocManAddrIfId.items():
            local_ips.add(read_ipv4_from_oid_tail(oid))

        lldpLocSysName = walk(host, '1.0.8802.1.1.2.1.3.3')
        lldpLocSysDesc = walk(host, '1.0.8802.1.1.2.1.3.4')

        this_bridge = Bridge(
            chassis_id=lldpLocChassisId,
            ip_addresses=list({host} | local_ips),
            name=next(iter(lldpLocSysName.values())),
            desc=next(iter(lldpLocSysDesc.values())) or '',
            neighbors=[],
            ports=defaultdict(lambda: Port(name='', speed=0, remote_macs=[], remote_ips=[], local_mac=None, interlink=False)))

        # Find IP addresses to neighbor bridges
        print(" - Getting neighbors...", file=sys.stderr)
        lldpRemManAddrTable = walk(host, '1.0.8802.1.1.2.1.4.2.1.4', 'preview')
        for oid, port_id in lldpRemManAddrTable.items():
            time_mark, local_port_num, rem_index, addr_subtype, *rest = split_numbers(oid)
            if addr_subtype == 1:  # ipv4
                if do_recurse:
                    ips_to_visit.add(read_ipv4_from_oid_tail(oid))

        # Port names
        print(" - Getting ports...", file=sys.stderr)
        for port, name in walk(host, '1.3.6.1.2.1.31.1.1.1.1', 'any').items():  # ifName
            this_bridge.ports[int(port)].name = name
        # Port speeds
        for port, speed in walk(host, '1.3.6.1.2.1.31.1.1.1.15', 'int').items():  # ifHighSpeed
            this_bridge.ports[int(port)].speed = speed
        # Local port macs
        for port, mac in walk(host, '1.3.6.1.2.1.2.2.1.6', 'hex').items():  # ifPhysAddress
            this_bridge.ports[int(port)].local_mac = mac
            all_bridge_macs.add(mac)

        # Read ARP table
        print(" - Reading device ARP table...", file=sys.stderr)
        atPhysAddress = walk(host, '1.3.6.1.2.1.3.1.1.2', 'hex')
        for oid, mac in atPhysAddress.items():
            ip = read_ipv4_from_oid_tail(oid, with_len=False)
            arp[ip] = mac

        # Map remote (learned) MACs to ports
        print(" - Getting MACs for ports...", file=sys.stderr)
        macs_per_port = defaultdict(set)
        ports_per_mac = defaultdict(set)
        dot1qTpFdbPort = walk(host, '1.3.6.1.2.1.17.7.1.2.2.1.2', 'int')
        for k, port_idx in dot1qTpFdbPort.items():
            port = port_idx
            if port_idx in dot1dTpFdbPort_to_portnum:
                port = dot1dTpFdbPort_to_portnum[port_idx]
            parts = split_numbers(k)
            vlan = int(parts[0])
            if port:
                mac = ''.join([('%02x' % x) for x in parts[1:]])
                if mac != '0000000000':
                    assert(port in this_bridge.ports)
                    if mac not in this_bridge.ports[port].remote_macs:
                        this_bridge.ports[port].remote_macs.append(mac)
                    macs_per_port[port].add(mac)
                    ports_per_mac[mac].add(port)

        #lldpRemSysCapSupported = walk(host, '1.0.8802.1.1.2.1.4.1.1.11', 'hex')
        ##lldpLocSysCapSupported = int(tuple(walk(host, '1.0.8802.1.1.2.1.3.5', 'hex').values())[-1], 16)
        ##is_bridge = (lldpLocSysCapSupported & 32) != 0
        #print(lldpRemSysCapSupported,  file=sys.stderr)

        print(" - Getting remotes...", file=sys.stderr)
        lldpRemChassisId = walk(host, '1.0.8802.1.1.2.1.4.1.1.5', 'hex')
        for k, chassis_id in lldpRemChassisId.items():
            time_mark, port, idx = split_numbers(k)
            if chassis_id not in this_bridge.neighbors:
                this_bridge.neighbors.append(chassis_id)

        this_bridge.ports = dict(this_bridge.ports)
        bridges[this_bridge.chassis_id] = this_bridge


    # Just to be sure: lookup MACs for visited bridge IPs
    for ip, mac in arp.items():
        if ip in visited_ips:
            all_bridge_macs.add(mac)

    # Reverse ARP table (MAC -> set of IPs)
    rarp = {}
    for k, v in arp.items():
        rarp.setdefault(v, set()).add(k)

    # Find hostnames for ip addresses using multiple threads (the query is VERY slow)
    ip_to_hostname = {}
    with PoolExecutor(max_workers=50) as executor:
        ips = []
        for b in bridges.values():
            ips.extend(b.ip_addresses)
            for p in b.ports.values():
                for mac in [*p.remote_macs, p.local_mac, b.chassis_id]:
                    ips.extend(rarp.get(mac) or [])
        ips = set(ips)

        def fetch_name(ip):
            try:
                return socket.gethostbyaddr(ip)
            except (socket.gaierror, socket.herror):
                return [None, [], [ip]]

        if resolve_hostnames:
            print(f"Resolving hostnames for {len(ips)} IP addresses...", file=sys.stderr)
            for res in executor.map(fetch_name, ips):
                for ip in res[2]:
                    if res[0]:
                        ip_to_hostname[ip] = res[0]

    # Cleanup and extend some values
    print("Cleaning up and extending...", file=sys.stderr)
    for b in bridges.values():
        print(f" - Bridge {b.name}...", file=sys.stderr)

        # Replace macs with NeighborInfos in neighbor lists
        print("   - extending NeighborInfos...", file=sys.stderr)
        neigh_infos = []
        for chassis_id in b.neighbors:
            ni = NeighborInfo(is_bridge=False, name='', ips=[], macs=[chassis_id], chassis_id=chassis_id)
            b2 = bridges.get(chassis_id)
            if b2:
                ni = NeighborInfo(is_bridge=True, name=b2.name, ips=list(b2.ip_addresses), chassis_id=chassis_id,
                                  macs=list({chassis_id, *[p.local_mac for p in b2.ports.values()]}))

            ni.in_ports = list({k for k,p in b.ports.items() if (set(ni.macs).intersection(set(p.remote_macs)))})
            for ips in ((rarp.get(m) or []) for m in ni.macs):
                ni.ips.extend(ips)
            ni.ips = list(set(ni.ips))
            ni.name = ni.name or ip_to_hostname.get([*ni.ips, ''][0]) or ''
            neigh_infos.append(ni)

        b.neighbors = neigh_infos

        # Delete unused ports from results
        if not all_ports:
            print("   - filtering unused ports...", file=sys.stderr)
            b.ports = {k: v for k, v in b.ports.items() if (v.remote_macs or v.remote_ips)}

        # Update port contents
        print("   - updating port contents...", file=sys.stderr)
        for p in b.ports.values():
            # Mark all ports with bridge management addresses as "interlink"
            for bm in all_bridge_macs:
                p.interlink |= (bm in p.remote_macs)
            # Add a list of IP addresses seen behind a port
            for mac in p.remote_macs:
                p.remote_ips.extend(rarp.get(mac) or [])
            p.remote_macs = sorted(p.remote_macs)
            p.remote_ips = sorted(list(set(p.remote_ips)))  # prune duplicates

    # Sort for nicer output  TODO: "natural sorting" for IPs
    print("Sort ARP tables...", file=sys.stderr)
    arp = dict(sorted(arp.items()))
    rarp = dict(sorted(rarp.items()))

    res_dict = {
        'timestamp': time.time(),
        'bridges':  [b.as_dict() for b in bridges.values()],
        'arp': arp,
        'rarp': {k: list(v) for k, v in rarp.items()},
        'ip_to_hostname': ip_to_hostname
    }

    return bridges, arp, rarp, ip_to_hostname, json.dumps(res_dict, indent=4)


def main():
    parser = argparse.ArgumentParser(description="LLDP/SNMP switch mapper. Queries networking info on given IPs and neighbors.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('ip', nargs='+', help="Server to start query recursion from.")
    parser.add_argument('-c', '--community', dest='snmp_community', type=str, default='public', help='SNMP community')
    parser.add_argument('-nr', '--norec', dest='no_recursion', action='store_true', default=False, help="Don't recurse; visit only given IPs.")
    parser.add_argument('-nh', '--nohostnames', dest='no_hostnames', action='store_true', default=False, help="Don't resolve hostnames.")
    parser.add_argument('-ap', '--all-ports', dest='all_ports', action='store_true', default=False, help="Show empty/disconnected ports, too.")
    parsed = parser.parse_args()

    bridges, arp, rarp, ip_to_hostname, json_res = process_hosts(
        parsed.ip, community=parsed.snmp_community, do_recurse=not parsed.no_recursion,
        all_ports=parsed.all_ports, resolve_hostnames=not parsed.no_hostnames)
    print(json_res)

if __name__ == "__main__":
    main()
