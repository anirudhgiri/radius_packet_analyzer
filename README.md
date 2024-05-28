# RADIUS Packet Analyzer

A simple and easy-to-use CLI tool to sniff/intercept RADIUS packets and analyze it's contents. The program listens on UDP port 1812, and parses any packet it intercepts according to [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865.html).

## Features

- Prints the contents of a RADIUS packet in a human-readable format
- Operates in two modes:
  - **Capture Mode** - Prints the contents of RADIUS packets sent to the tool by a RADIUS client (does not forward it to a server).
  - **Proxy Mode** - Prints the contents of RADIUS packets sent to the tool by a RADIUS client, and forwards it to a RADIUS server, also printing the contents of its responses.

## Usage

### Installation

- `git clone https://github.com/anirudhgiri/radius_packet_analyzer`
- `cd radius_packet_analyzer`
- `chmod +x ./radius_packet_analyzer.py`

### Running the Tool

#### Command Execution

Execute the script with the following command:

```bash
./radius_packet_analyzer.py
```

This will start the RADIUS packet analyzer, enabling you to monitor and analyze RADIUS traffic. By default, the tool will intercept any RADIUS packets sent to port 1812 and print it's contents to the standard output.

#### Command Options

| Flag          | Description                                                                                      | Usage Example                                           |
| ------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| -p, --port    | The UDP port to listen on.<br>`default: 1812`                                                    | `--port 1812`, `-p 1812`                                |
| -f, --forward | The address of the RADOUS server to forward the packet to after interception.<br>`default: none` | `--forward 192.168.0.101:1812`, `-f 192.168.0.101:1812` |

#### Running on Capture Mode

1. Run the analyzer using `./radius_packet_analyzer.py -p <port>`
2. Send a RADIUS packet to the analyzer using by pointing your WiFi Access Point to it, or by running `radtest -x <username> <password> 127.0.0.1:<port> 0 testing1234`

This will send an `Access-Request` packet to the analyzer running on the specified port (1812 by default), which will print the contents of the packet. The client will not recieve a response as the packet was not forwarded to a RADIUS server.

#### Running on Proxy Mode

1. Start your RADIUS server. Let's assume for the purposes of this example that it's running on port 1812 in a computer on your network with the IP `192.168.0.101`.
2. Start the analyzer using `./radius_packet_analyzer.py -p <port> -f 192.168.0.101:1812`
3. Send a RADIUS packet to the analyzer using by pointing your WiFi Access Point to it, or by running `radtest -x <username> <password> 127.0.0.1:<port> 0 <shared_secret>`

This will send an `Access-Request` packet to the analyzer running on the specified port (1812 by default), which will print the contents of the packet. The analyzer will then forward the packet over to the RADIUS server on the specified address, recieve and print the contents of it's response, and forward it back to the client.
