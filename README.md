# FAAP
Foreber Alone AP - Kick off connected STA from a AP, be gready and keep all the brad band ;)

# I wrote this just because I need wide broadband in shared WLAN !!
# So how it works!
# Requirements: Debian core OS, Python 2.7 and Scapy.
# This script sends deauthentication packets towards the clients connected to a specific AP
#
# How to Run it:
# FAAP.py BSSID interface channel safe_STA
#####BSSID = BSSID u r connected to - AP
#####interface: a monitor interface capable of inject traffic
#####Channel: the frequency channel the AP is working on
#####safe_STA: the client MAC address
# Feel free of share and modify
