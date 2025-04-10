# trafficanalysis
simple network traffic analysis with scapy and streamlit

Not much happening here. I touched on some basic threading capabilities, and Scapy - which was a joy to use.
However, the use of streamlit for the UI here was not the best call:

    The functionality relating to consistent, fast data flow between the threads, and the streamlit 
    browser application is shaky at best, and doesn't offer a whole lot in regards to capabilities for handling
    fast UI updates. It uses websockets which handle the raw data flow alright, but the UI refresh mechanisms
    really tank the whole thing - reruns are not at all suitable, and the containerised UI elements that can handle
    localised refreshes are too slow.

That being said; what streamlit does have going for it is that it is extremely quick and easy to set up.

You can dive a whole lot deeper with Scapy; https://scapy.readthedocs.io/en/latest/index.html
Personally, I was very interested in its capabilities of interacting with the windows API for network
adapter and interface information - that is a very powerful capability that I'd encourage anyone to read about.


