[NOT FINISHED]

# 🛜 Network Traffic Catcher

## Introduction

The purpose of this project is to filter traffic network and notify me when a connection to a non desired website or service from a device using the network occurs (like a Proxy).\
It was a good oppportunity for me to learn more about networks in general, and to get in touch with network and low-level programming.
<br/>
<br/>

## Technical informations

This project uses the following technologies :
- C++ language
- Visual Studio 2022
- Npcap C library
- Windows Sockets 2 library

The choice of the C++ language was a little obvious in my case because of the fact that I wanted to use low-level features for educational purposes (pointers and dynamic memory allocation). But C++ offers the possibility of Object-Oriented Programming (OOP), essential for setting up an efficient and comprehensible structure, unlike the C language.

Concerning Npcap's choice, it is a very popular library used in tools such as Nmap or Wireshark (see [Npcap's documentation](https://npcap.com/)). Since it exists in C, its use became obvious.

Windows Sockets 2 exists natively in Windows and especially in Visual Studio 2022, so no need to install it in my case. I used it in order to to resolve IPv4 addresses from selected domain names (more informations at [issues encountered](#issues-encountered-during-development) section).
<br/>
<br/>

## Issues encountered during development

### Npcap's setup in Visual Studio 2022

--> DETAIL
<br/>
<br/>

### Promiscuous mode

Not all Network Interface Cards (NIC) support the <i>Promiscuous Mode</i> and we can discover it thanks the following PowerShell command which lists interfaces and returns `True` or `False` for each one :
```
Get-NetAdapter | Format-List -Property PromiscuousMode, Name
```

This mode allows the NIC to listen the entire network and not only packets destined to the NIC itself. It means that it can catch connections from all devices in the same network. The issue is that my NIC doesn't support Promiscuous Mode, so I need to create a Hotspot with my PC and to connect all devices to it in order to catch transiting packets (my PC must act as a <i>man-in-the-middle</i> in this case).
<br/>
<br/>

### IPv4 Resolving from domain name

- Resolving DNS IP addresses : if we want to notify when a connection to a specified website occurs, we need to get the DNS name linked to the IP address, here's why :
  - Let's say that we want to notify when a connection to www.stackoverflow.com occurs.\
      When we run the following command `Resolve-DnsName -Name www.stackoverflow.com -Type A | Select IPAddress` in a PowerShell prompt, we can get one or many     IPv4 addresses.\
      So it means that we can't filter on IPv4 addresses but only on DNS names in order ensure that all connections to stackoverflow will be notified, and not only some of them if many IPv4 addresses exist.
  - PROBLEM : It's not easy to resolve the DNS name when we capture the packet from the IP address
      - Either we need to run a powershell script with the above command, but many issues appear :
        - This solution needs to be adapted depending on the operating system (PowerShell for Windows, any other Shell for Unix based systems)
        - In Windows especially, we need to manipulate the script in order to be able to call it (Set-ExecutionPolicy to RemoteSigned and Unblock-File <path_to_file>) but it opens security problems by changing rights scripts execution
        - It's more costly in terms of resources.

So the solution was to use the Windows Socket 2 library (with the `ws2tcpip.h` header), which was a little bit touchy to understand but works really well.
