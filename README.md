(NOT FINISHED)

The purpose of this project is to filter traffic network and notify me when a connection to a non desired website or service occurs from a device using the network (like a Proxy).
It is a good oppportunity for me to learn more about networks in general, and to get in touch with network and low-level programmation.

Issues encountered for the moment :
- Npcap's setup in Visual Studio 2022 (I'll detail later)
- My PC can not scan all the network because my PC's network card does not support the "Promiscuous Mode", it means that it can only scan its own connections (or other devices connected by hotspot to this Laptop)

- Resolving DNS IP addresses : if we want to notify when a connection to a specified website occurs, we need to get the DNS name linked to the IP address, here's why :
  --> Let's say that we want to notify when a connection to www.stackoverflow.com occurs.
      When we run the following command "Resolve-DnsName -Name www.stackoverflow.com -Type A | Select IPAddress" in a powershell prompt, we can get one or many IP addresses.
      So it means that we can't filter on IP addresses but only on DNS names in order ensure that all connections to stackoverflow will be notified, and not only some of them if many IP addresses exist.
  --> PROBLEM : It's not easy to resolve the DNS name when we capture the packet from the IP address
      - Either we need to run a powershell script with the above command, but many issues appear :
        --> This solution needs to be adapted depending on the operating system (powershell for windows, bash for linux)
        --> In Windows especially, we need to manipulate the script in order to be able to call it (Set-ExecutionPolicy to RemoteSigned and Unblock-File <path_to_file>) but it opens security problems by changing rights scripts execution
        --> It's more costly in terms of resources
      - Or we use a specific module (like ws2tcpip.h) but is more difficult to get the DNS Name