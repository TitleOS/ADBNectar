# ADBNector
A WIP fork of [ADBHoney]("https://github.com/huuck/ADBHoney"). Medium interaction ADB honeypot designed for Android Debug Bridge over TCP/IP.

## What's this?
The Android Debug Bridge (ADB) is a protocol designed to keep track of both emulated and real phones/TVs/DVRs connected to a given host. It implements various commands designed to assist the developer (`adb shell`, `adb push`, and so on) in both debugging and pushing content to the device. This is usually done via an attached USB cable, with ample mechanisms of authentication and protection. Turns out though that by a simple adb command (`adb tcpip <port>`) sent to an already established connection (through USB for example), you can force your device to expose its ADB services over port 5555, after which you can use a simple `adb connect <ip>:<port>` to connect to your device via TCP. However, unlike the USB protocol, the TCP one does not have any kind of authentication and leaves the device prone to all kinds of attacks. Two of them are as follows:

`adb shell <shell command>` - allows a developer to run all kinds of commands on the connected device such as ls, wget and many others.

`adb push <local file> <remote destination>` - allows a developer to upload binaries from his own machine to the connected Android device.

Coupled together, these two API calls can allow complete control over the device (legitimate or not) as long as the port is exposed over the Internet.
  
The purpose of this project is to provide a medium interaction honeypot designed to catch whatever malware is being pushed by attackers to unsuspecting Android victims which have port 5555 exposed and ADB enabled.

## How often are black hats really scanning the internet for ADB enabled Android devices and how many could there possibly be?
As of July 2025, a simple Shodan search query for product:”Android Debug Bridge” reveals 12k+ results. Of course, some of these could be honeypots themselves. As for the number of active attackers looking for ADB victims, three well known botnets based on exploiting Android via ADB. Trinity, ADB.Miner, and Fbot have had 10k+ devices at peak. Given that a majority of budget Chinese Android TV boxes and other devices come shipped from the factory with ADB enabled as well, this maks for a significant, while not massive drive to exploit ADB by current attackers.


## What works?"
Right now you can `adb connect`, `adb push` and `adb shell` into it. All of the data is redirected to stdout and files will be saved to disk. CPU/memory usage should be fairly low, any anormalities should be reported so they can be investigated.

Responses to shell commands can easily be added by editing the `adbnector\responses.py` file, a number of common commands have hardcoded responses, including a faked build.prop and other phone infomation to make it more difficult for the attacker to determine they are connected to a honeypot. All other commands will respond with `command not found`.

## What doesn't work?
More niche commands or truly interactive commands will not work at this time. Down the road, I may look into running a small lanaguage model >1b locally on CPU to generate on-the-fly realistic responses if needed.

# OK OK, how do I get it started?
Just start the script in python:

`nohup python3 run.py &`

Just like that, shouldn't have any more complex dependencies.

**The config file `adbnector.cfg` must be in the same directory as run.py or at `/etc/adbnector.cfg`**

Or give the docker container a try, easiest with docker-compose:

`docker-compose up --build -d` 

or without docker compose

`docker build -t adbnector:latest .`

`docker run --name adbnector --rm -p 5555:5555 -v $(pwd)/adbnector.cfg:/etc/adbnector.cfg adbnector:latest`

You will probably want to save uploads and logs to the host machine, so add these volumes to the run command above `-v $(pwd)/dl:/adbnector/dl -v $(pwd)/logs:/adbnector/logs`

## Credits

Massive props to [ADBHoney]("https://github.com/huuck/ADBHoney") by [@huuck]("https://twitter.com/hookgab"), the original project that ADBNector is a fork of.