# trafficanalysis
simple network traffic analysis with scapy and streamlit

Not much happening here. The combination of streamlit and scapy, I've found, is pretty bad for this purpose.

The functionality relating to consistent, fast data flow between the backend, and the streamlit 
browser application is shaky at best, and doesn't offer a whole lot in regards to capabilities for handling
fast processing. It uses websockets which handle the raw data flow alright, but the UI update mechanisms
really tank the whole thing - reruns are not at all suitable, and the containerised UI elements that can handle
localised refreshes are too slow.

Regardless, Streamlit is a very easy way to get a decent UI set up, and paired with the dream team duo that is 
pandas and plotly, works fine for 'real time' (give or take a few seconds of delay) data displays.

So, the real beauty here is the scapy library. I'd recommend taking it and pairing it with a fastapi, or node (sockets)
stack. 


