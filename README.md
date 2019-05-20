# FvS - Fake WiFi AP

This script sets up an open WiFi Access Point with a phishing captive portal to gather
credentials from unsuspecting victims.

## How do I use it?

Just run`./captive-portal.sh` and read the help message:

```
WiFi Captive Portal script
Foo-Manroot
2019

Usage:
	./captive-portal.sh <INET_iface> <AP_iface>

Args:
	INET_iface:
		Interface connected to the internet

	AP_iface:
		Wireless interface to set up as an AP. Will be started in monitor mode.


Environment variables. To use them to configure the AP properties, you can either
`export <VAR_NAME>=<whatever>` and then run this script, or directly execute this
script using `env <VAR_NAME>=<whatever> ./captive-portal.sh ...`

	HOLD: set it to '-hold' to keep the xterm windows up even after the process
		being executed dies. This can be used to debug the script and see why it
		isn't working

	ESSID: set it to whatever string you want. This will be the name used by your AP.
```

## Why should I use it, instead of other tools?

I tried to use other tools, but none of them really suited my needs. They were overly
complicated and I was only looking for a "big red button" to quickly set up a phishing
AP. So I decided to [automate](https://xkcd.com/1319/) the process myself to just run it
and being ready to go, with no configuration needed.

My reference starting point was [PwnSTAR](https://github.com/SilverFoxx/PwnSTAR). My
major concern about it (and most of the other tools) is that, when we connect to a real
network where we need to register, we are redirected immediately to a captive portal.
However, with these phishing APs, that functionality doesn't work really well, and most
devices end up disconnecting after probing the AP and seeing that there's no internet.

This is because, when setting up the AP, we usually use very simple firewall rules that
"do the trick". But that wasn't enough for me.


Of course, you're free to use any of the gazillions of alternative tools:
	- [Fluxion](https://github.com/wi-fi-analyzer/fluxion)
	- [PwnSTAR](https://github.com/SilverFoxx/PwnSTAR)
	- [WiFi-Pumpkin](https://github.com/P0cL4bs/WiFi-Pumpkin)
	- [WifiPhisher](https://github.com/wifiphisher/wifiphisher)
	- (...)


## What does 'FvS' mean?

No one will ever know... MUAHAHAHAHAHA

## References

After searching through all the internet to find a way to correctly create an AP with a
captive portal, I finally ended up in [Andrew Rippler's](https://andrewwippler.com/2016/03/11/wifi-captive-portal/)
web. There are the firewall rules that I was looking for, necessary to redirect all
clients to our captive portal upon connecting.
