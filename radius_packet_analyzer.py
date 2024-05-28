#!/usr/bin/python3
import click
import socket
import sys

def validate_forward_address(forward_address: str) -> tuple:
	split_address = forward_address.split(":")
	if len(split_address) != 2:
		print("error: Invalid forward address. Must be in the form <address>:<port>")
		sys.exit(1)
		
	[ip, port] = split_address

	split_ip = ip.split(".")
	if len(split_ip) != 4:
		print("error: invalid forward address. IP address must have 4 octets")
		sys.exit(1)

	for octet in (split_ip):
		if not octet.isdigit() or int(octet) < 0 or int(octet)>255:
			print("error: invalid forward address. IP address must have 4 octets")
			sys.exit(1)

	if not port.isdigit() or int(port) < 1 or int(port) > 65535:
		print("error: Invalid forward address port. Must be in the range 1 <= port <= 65535")
		sys.exit(1)
	
	return (ip, int(port))


@click.command()
@click.option("-p","--port", default=1812,type=click.IntRange(min=1,max=65535), help="The UDP port to listen on. (default: 1812)")
@click.option("-f","--forward","forward_address", help="The address of the RADIUS server to forward incoming packets to after interception.")
def main(port, forward_address):
	if forward_address != None:
		forward_address = validate_forward_address(forward_address)
	start_analyzer(port, forward_address)

def start_analyzer(port, forward_address):
	# create a UDP socket
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# bind the socket to the port specified through the --port option (default: 1812)
	sock.bind(("0.0.0.0",port))
	print(f"Listening on port {port}...")

	identifier_dict = {}

	# listen for messages from the newly-bound UDP socket
	while True:
		data,address = sock.recvfrom(4096)
		print(f"RADIUS packet recieved from {address[0]}:{address[1]}")

		code = data[0] # the packet code is in the first byte
		print(f"Code: {code}")

		identifier = data[1] # the packet identifier is in the second byte
		print(f"Identifier: {identifier}")

		packet_length = (data[2] << 8) + data[3] # the packet length is in the third and fourth byte
		print(f"Length: {packet_length}")

		authenticator = data[4:20] # the authenticator is in the next sixteen bytes
		print(f"Authenticator: {list(authenticator)}")

		# start from the twentieth byte, and keep interpreting the attribute data until the end of the packet 
		i = 20
		while i < packet_length:
			attribute_type = data[i] # the attribute type is in the first byte
			i+=1
			print(f"Attribute Type: {attribute_type}")

			attribute_length = data[i] - 2
			i += 1
			print(f"Attribute Length: {attribute_length}") #the attribute length is in the second byte

			attribute_value = data[i:i+attribute_length] # the attribute value is in the next n bytes, where n = attribute_length
			i += attribute_length
			# if the attribute_type is User-Name, convert the attribute_value to a string
			if attribute_type == 1:
				attribute_value = bytes.decode(attribute_value, "utf-8")
			# else, convert it to a byte array
			else:
				attribute_value = list(attribute_value)

			print(f"Attribute Value: {attribute_value}")
		
		if forward_address != None:
			if address != forward_address:
				identifier_dict[identifier] = address
				sock.sendto(data,forward_address)
			else:
				sock.sendto(data,identifier_dict[identifier])
				identifier_dict.pop(identifier)

if __name__ == "__main__":
	main()
