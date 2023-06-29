# DNS Server Implementation

This project's goal is to implement a local DNS resolver using the socket API to resolve a hostname's IP address. We apply the iterative strategy to resolve DNS queries by consulting the root name server, the TLD (Top Level Domain) name server, and finally, the authoritative DNS server to get the IP address of the requested hostname.

## Getting Started

These instructions will guide you on how to run the project on your local machine.

### Prerequisites

You need Python 3.x installed on your machine.

### Running the Code

This Python program should be run from the command line as follows:

```sh
python3 dns_resolver.py www.tmz.com

## Code Structure

The code mainly consists of the following functions:

- `message(url)`: Constructs the DNS query request according to RFC 1035.
- `send_message(message, address, port=53)`: Sends the DNS query to the given IP address over UDP and returns the response.
- `response_unpack(data)`: Parses the response data from the server, extracting necessary information.
- `getHost(data, start_idx)`: Retrieves the hostname from the response message.
- `ip_hostname(hostname)`: Orchestrates the iterative process of consulting different DNS servers to resolve the hostname's IP address.

## Workflow

The process this DNS server follows includes:

1. Build a DNS query request according to RFC 1035.
2. Send the DNS query to one of the root servers using UDP on port 53.
3. Wait for the response and move to the next root server if there is no response within a certain timeframe.
4. Parse the received response to understand the contents of the message.
5. Check the Resource Records (RRs) in the Additional section of the DNS response and print out the IP address of each DNS server that we call.
6. Continue the process by consulting the TLD server and authoritative DNS server.
7. Once the IP address for the A record has been received from the authoritative name server, return it to the DNS client.

## Output

The output of the program includes:

- The IP addresses of each DNS server we have contacted (root, TLD, and authoritative).
- The resolved IP address of the A record for the hostname.

## Performance Analysis

To evaluate the performance of our DNS server, we calculate the Round-Trip Time (RTT) to each of the DNS servers including the root name server, the TLD name server, and the authoritative DNS server of the queried hostname.

## Future Enhancements

While the current implementation already delivers reliable DNS resolution, the following improvements can be considered for the future:

- DNS caching: Save the response from a DNS server for a particular domain to prevent the need to resolve it again in the future.
- Handling CNAMES: Implement logic to correctly handle CNAME records, which are used for domain aliases.
- Support for more record types: Currently, our DNS resolver only handles A records. We could enhance it to support other types like MX, TXT, etc.
- Concurrency: To improve the performance, the application can be made to resolve multiple DNS requests concurrently.
