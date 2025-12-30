📡 wp-xmlrpc_whisperer

A Python tool to probe and interact with WordPress’s XML-RPC endpoint (xmlrpc.php) for security research and testing purposes. Some security teams and pentesters dismiss XML-RPC as “legacy,” but vulnerabilities in this interface — especially related to remote calls and authentication amplification — remain relevant for effective assessments. 



🧠 What Is This For?

WordPress includes an XML-RPC interface (xmlrpc.php) that allows remote procedure calls. While originally designed for mobile publishing and legacy services, it has been repeatedly abused by attackers for:

brute force amplification attacks

credential guessing via system.multicall

bypassing standard login protections

other vector exploration in authorized testing contexts 


wp-xmlrpc_whisperer is designed to help security practitioners demonstrate real impact from exposed XML-RPC endpoints — especially when other tooling is unreliable or inconsistent. 


⚠️ This tool is intended for authorized security testing only. Do not use against systems without explicit permission.



🚀 Features

Interact with WordPress XML-RPC endpoints

Send custom method calls (e.g., wp.getUsersBlogs, system.multicall)

Support multiple payload patterns for security testing

Collect and report XML-RPC responses for analysis

This project is not a generic brute-force script  it’s meant to empower structured testing workflows.
