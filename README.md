
# 🛜 Network Traffic Catcher

## Introduction

The purpose of this project is to filter traffic network and notify me when a connection to a non desired website or service from a device using the network occurs (like a Proxy).

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

## Demonstration (V0)

<img src="https://github.com/user-attachments/assets/e19a086c-c15a-4d6c-ac34-dd79adea73c1" alt="Demo image" width="512">\

The project is not finished, but here you can see how it globally works. In this example, the `DEVICE INFO` text in the results will be changed with the client who is trying to connect informations (IP Address, Name or whatever...).
<br/>
<br/>

## Issues encountered during development

### - Npcap's setup in Visual Studio 2022

First of all, I needed to download the [Npcap 1.80 installer](https://npcap.com/#download) (or a newer version) and to install it because our app needs Npcap's dlls to run.

Once the installation is done, we need to download the [Npcap SDK 1.13 ZIP file](https://npcap.com/#download) (or a newer version) and to unzip it to an easily accessible folder.

Then it becomes a little bit tricky. I needed to configure my Visual Studio project to add external libraries, includes and additional directories. I went to Project > Properties > Configuration Properties and then I modfied some settings among all the listed ones in different sections :
- Firstly I went to Linker > General > Additional Library Directories and edited it to add the absolute path to my `Lib` directory of the Npcap folder like `C:\npcap\folder\Lib`
- Secondly I went to Linker > Input > Additional Dependencies and added the two following lines
```
C:\npcap\folder\Lib\x64\wpcap.lib
C:\npcap\folder\Lib\x64\Packet.lib
```
- Finally I went to C/C++ > General > Additional Include Directories and added the `C:\npcap\folder\Include` path.

No need to manipulate PATH variables.
<br/>
<br/>

### - Promiscuous mode

Not all Network Interface Cards (NIC) support the _Promiscuous Mode_ and we can discover it thanks the following PowerShell command which lists interfaces and returns `True` or `False` for each one :
```PowerShell
Get-NetAdapter | Format-List -Property PromiscuousMode, Name
```

This mode allows the NIC to listen the entire network and not only packets destined to the NIC itself. It means that it can catch connections from all devices in the same network. The issue is that my NIC doesn't support Promiscuous Mode, so I need to create a Hotspot with my PC and to connect all devices to it in order to catch transiting packets (my PC must act as a _man-in-the-middle_ in this case).
<br/>
<br/>

### - IPv4 Resolving from domain name

If we want to notify when a connection to a specified website occurs, we need to get the DNS name linked to the IP address, here's the explanation why.

Let's say that we want to be notified when a connection to www.stackoverflow.com occurs.

When we run `Resolve-DnsName -Name www.stackoverflow.com -Type A | Select IPAddress` in a PowerShell prompt, it can return one or many IPv4 addresses depending on the website. It means that we can't filter on IPv4 addresses but only on DNS names in order to ensure that all connections to www.stackoverflow.com will be notified and not only a part. This is because some domains may have multiple servers for reliability and performance reasons.

The main problem is that it is not easy to resolve the DNS name when we capture the packet from the IP address.\
Either we need to run a powershell script with the above command, but many issues appear :
  - This solution must be adapted depending on the operating system (PowerShell for Windows, any other Shell for Unix based systems)
  - In Windows especially, we need to modify execution rights on PowerShell scripts in general with `Set-ExecutionPolicy to RemoteSigned and Unblock-File <path_to_file>` in order to be able to call it, however it opens security problems. In Windows it is not possible to change executions rights for only one script, either we do it for all or we do not.
  - It is not really performant.

So the solution was to use the _Windows Socket 2_ library (with the `ws2tcpip.h` header), which was a little bit touchy to understand but works really well.

[More to come...]
