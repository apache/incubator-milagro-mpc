# Vagrant

[vagrant](https://www.vagrantup.com/) is a tool that allow for simple
management of virtual machines (VMs) in code.

## Installation

```
sudo apt install vagrant*
```

Virtual box is required. Download the AMD64 verson from here;

```
https://www.virtualbox.org/wiki/Linux_Downloads
```

## Configuration

The VM is configured in the Vagrantfile. This file
also call a bootstrap.sh script which installs the
required software.

When the VM is started there is a shared directory
between the VM and the host at /vagrant. Any files
that are in the directory containing this README
will be available on /vagrant.

For example to have this repo available on the VM.

```
git clone git@gitlab.com:qredo/libmpc.git
```

in this directory and then on the VM

```
mv /vagarnt/libmpc $HOME
```

## Commands

Start VM (this will run provisioner i.e. commands in bootstrap.sh)

```
vagrant up
```

Log onto VM

```
vagrant ssh
```

Stop the VM

```
vagrant halt
```

Stop and delete VM

```
vagrant destroy
```

Run provision script again

```
vagrant up --provision
```