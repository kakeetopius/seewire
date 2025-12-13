# Things to implement and improve in due course.

1. Refactoring.
    - For every module(packet handler) add a protocol strutcure in ascii to show the header format.
    - Refactor code in each module to use new prinitng functions
    - add another printing function to print application layer fields. like dns, smtp etc
    - break down source code files it different folders like protocols, util etc. 
    - Find a better way of also managing include files in c.
    - Switch from Make file to something like meson/ninja
    - Remove big functions from main.c and put it in other modules.
2. Output of Packet Headers
    - Add an option to print detailed or print concise.
3. DNS module.
    - Change the function that handles priting of dns domain names to be more understable and prevent recursion.
4. HTTP module.
    - Change the handling of http data. Try to read headers and extract fields.
    - Try to implement a way to display http data that is split into multiple packets as a single entity.
5. Support For other Protocols.
    - WLAN 802.11 frames
    - ICMPv4 and ICMPv6
    - SMTP
    - IPv6

