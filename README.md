# Fingerpy

Fingerpy is a lightweight, Python network flow fingerprinting tool that passively captures traffic, aggregates it into flows, classifies likely services by port, prints top talkers to the terminal and stores structured results in SQLite for later analysis.

It uses the Scapy library to capture packets at the NIC level. 

__________________________________________________________________________________
**Installation** 
Written in Python 3.13.9 (3.9+ Recommended)
Root/Administrator Privilege
pip install Scapy
_________________________________________________________________________________
Currently is used to scope network traffic and understand the topology of the system. Plans to implement service health checks soon. May implement an IDS in the future, or some sort of deep-learning anomoly detection.
