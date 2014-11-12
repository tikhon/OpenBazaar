#!/bin/bash

#
# configure.sh - Setup your OpenBazaar development environment in one step.
#
# If you are a Ubuntu or MacOSX user, you can try executing this script
# and you already checked out the OpenBazaar sourcecode from the git repository
# you can try configuring/installing OpenBazaar by simply executing this script
# instead of following the build instructions in the OpenBazaar Wiki
# https://github.com/OpenBazaar/OpenBazaar/wiki/Build-Instructions
#
# This script will only get better as its tested on more development environments
# if you can't modify it to make it better, please open an issue with a full
# error report at https://github.com/OpenBazaar/OpenBazaar/issues/new
#
#

#exit on error
set -e

function command_exists {
  # this should be a very portable way of checking if something is on the path
  # usage: "if command_exists foo; then echo it exists; fi"
  type "$1" &> /dev/null
}

function brewDoctor {
    if ! brew doctor; then
      echo ""
      echo "'brew doctor' did not exit cleanly! This may be okay. Read above."
      echo ""
      read -p "Press [Enter] to continue anyway or [ctrl + c] to exit and do what the doctor says..."
    fi
}

function brewUpgrade {
    echo "If your homebrew packages are outdated, we recommend upgrading them now. This may take some time."
    read -r -p "Do you want to do this? [y/N] " response
    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]
    then
      if ! brew upgrade; then
        echo ""
        echo "There were errors when attempting to 'brew upgrade' and there could be issues with the installation of OpenBazaar."
        echo ""
        read -p "Press [Enter] to continue anyway or [ctrl + c] to exit and fix those errors."
      fi
    fi
}

function installMac {
  # print commands (useful for debugging)
  # set -x  #disabled because the echos and stdout are verbose enough to see progress

  # install brew if it is not installed, otherwise upgrade it
  if ! command_exists brew ; then
    echo "installing brew..."
    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
  else
    echo "updating, upgrading, checking brew..."
    brew update
    brewDoctor
    brewUpgrade
    brew prune
  fi

  # Use brew's python 2.7, even if user has a system python. The brew version comes with pip and setuptools.
  # If user already has brew installed python, then this won't do anything. 
  # Note we get pip for free by doing this, and can avoid future calls to sudo. brew convention abhors all things 'sudo' anyway.
  brew install python

  for dep in gpg sqlite3 wget openssl zmq autoenv
  do
    if ! command_exists $dep ; then
      brew install $dep
    fi
  done

  # install python's virtualenv if it is not installed
  if ! command_exists virtualenv ; then
    pip install virtualenv
  fi

  # create a virtualenv for OpenBazaar. note we get env/bin/pip by doing this. We also needed pip earlier to install virtualenv.
  if [ ! -d "./env" ]; then
    virtualenv --python=python2.7 env
  fi

  # "To begin using the virtual environment, it needs to be activated:"
  # http://docs.python-guide.org/en/latest/dev/virtualenvs/
  # We have autoenv and an appropriate .env in our OB home dir, but we should activate the env just in case (e.g. for first time users).
  source env/bin/activate

  # set compile flags for brew's openssl instead of using brew link --force
  export CFLAGS="-I$(brew --prefix openssl)/include"
  export LDFLAGS="-L$(brew --prefix openssl)/lib"

  # install python deps inside our virtualenv
  ./env/bin/pip install -r requirements.txt

  # There are still pysqlcipher issues on OS X. Temporarily disable sqlite-crypt until that is resolved.
  doneMessage "--disable-sqlite-crypt "
}

function doneMessage {
  echo ""
  echo "OpenBazaar configuration finished."
  echo "type './openbazaar $1start; tail -f logs/production.log' to start your OpenBazaar servent instance and monitor logging output."
  echo ""
  echo ""
  echo ""
  echo ""
}

function installUbuntu {
  # print commands
  set -x

  sudo apt-get update
  sudo apt-get install python-pip build-essential python-zmq rng-tools
  sudo apt-get install python-dev g++ libjpeg-dev sqlite3 openssl
  sudo apt-get install alien libssl-dev python-virtualenv lintian libjs-jquery

  if [ ! -d "./env" ]; then
    virtualenv --python=python2.7 env
  fi

  ./env/bin/pip install -r requirements.txt

  doneMessage
}

function installArch {
  #print commands
  set -x

  sudo pacman -Sy
  # sudo pacman -S --needed base-devel
  # Can conflict with multilib packages. Uncomment this line if you don't already have base-devel installed
  sudo pacman -S --needed python2 python2-pip python2-virtualenv python2-pyzmq rng-tools libjpeg sqlite3 openssl

  if [ ! -d "./env" ]; then
    virtualenv2 env
  fi

  ./env/bin/pip install -r requirements.txt

  doneMessage
}

function confirm {
    # call with a prompt string or use a default Y
    read -r -p "Are you sure? [Y/n] " response
    if [[ $response =~ [nN](o)* ]]; then
      return 1
    else
      return 0
    fi
}

function installRaspiArch {
  # pacman -S sudo
  sudo pacman -Sy
  sudo pacman -S --needed base-devel curl wget python2 python2-pip rng-tools libjpeg sqlite3 openssl libunistring
  echo " "
  echo "Notice : pip install requires 10~30 minutes to complete."
  if confirm ; then
    pip2 install -r requirements.txt
    doneMessage
    echo "Run OpenBazaar on Raspberry Pi Arch without HDMI/VideoOut"
    echo "Type the following shell command to start."
    echo " "
    echo "IP=\$(/sbin/ifconfig eth0 | grep 'inet ' | awk '{print \$2}')"
    echo "./openbazaar --disable-open-browser -k \$IP -q 8888 -p 12345 start; tail -f logs/production.log"
  fi
}

function installRaspbian {
  sudo apt-get -y install python-pip build-essential rng-tools alien
  sudo apt-get -y install openssl libssl-dev gcc python-dev libjpeg-dev sqlite3
  echo " "
  echo "Notice : pip install requires 2~3 hours to complete."
  if confirm ; then
    sudo pip install -r requirements.txt
    doneMessage
    echo "Run OpenBazaar on Raspberry Pi Raspbian without HDMI/VideoOut"
    echo "Type the following shell command to start."
    echo " "
    echo "IP=\$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print \$1}')"
    echo "./openbazaar --disable-open-browser -k \$IP -q 8888 -p 12345 start; tail -f logs/production.log"
  fi
}

function installPortage {
  # print commands
  set -x

  sudo emerge -an dev-lang/python:2.7 dev-python/pip pyzmq rng-tools gcc jpeg sqlite3 openssl dev-python/virtualenv
  # FIXME: on gentoo install as user, because otherwise
  # /usr/lib/python-exec/python-exec* gets overwritten by nose,
  # killing most Python programs.
  pip install --user -r requirements.txt
  doneMessage
}

function installFedora {
  # print commands
  set -x

  sudo yum install -y http://linux.ringingliberty.com/bitcoin/f18/x86_64/bitcoin-release-1-4.noarch.rpm

  sudo yum -y install python-pip python-zmq rng-tools openssl \
  openssl-devel alien python-virtualenv make automake gcc gcc-c++ \
  kernel-devel python-devel openjpeg-devel sqlite \
   zeromq-devel zeromq python python-qt4 openssl-compat-bitcoin-libs

  if [ ! -d "./env" ]; then
    virtualenv env
  fi

  ./env/bin/pip install -r requirements.txt

  doneMessage
}


if [[ $OSTYPE == darwin* ]] ; then
  installMac
elif [[ $OSTYPE == linux-gnu || $OSTYPE == linux-gnueabihf ]]; then
  UNAME=$(uname -a)
  if [ -f /etc/arch-release ]; then
      if [[ "$UNAME" =~ alarmpi ]]; then
          echo "$UNAME"
          echo Found Raspberry Pi Arch Linux
          installRaspiArch "$@"
      else
          installArch
      fi
  elif [ -f /etc/manjaro-release ]; then
    installArch
  elif [ -f /etc/gentoo-release ]; then
    installPortage
  elif [ -f /etc/fedora-release ]; then
    installFedora
  elif grep Raspbian /etc/os-release ; then
    echo Found Raspberry Pi Raspbian
    installRaspbian "$@"
  else
    installUbuntu
  fi
fi
