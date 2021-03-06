#!/bin/bash
set -e
function unsupport_os() {
  echo "unsupport os." && exit 1
}
BASE_URL=https://github.com/pyama86/pam-google-web-oauth-rs/releases/download/v0.1.0/pam-google-web-oauth.so
UNAME=$(uname | tr "[:upper:]" "[:lower:]")
# If Linux, try to determine specific distribution
if [ "$UNAME" == "linux" ]; then
  # If available, use LSB to identify distribution
  if [ -f /etc/lsb-release -o -d /etc/lsb-release.d ]; then
    source /etc/lsb-release
    if test $DISTRIB_CODENAME = "stretch"; then
      DISTRIB_CODENAME=xenial
    elif test $DISTRIB_CODENAME = "buster"; then
      DISTRIB_CODENAME=bionic
    fi

    test $DISTRIB_CODENAME != "xenial" && test $DISTRIB_CODENAME != "bionic" && unsupport_os
    DISTRO=${DISTRIB_CODENAME}
    DEST=/lib/x86_64-linux-gnu/security/pam-google-web-oauth.so
  else
    rpm --eval %{centos_ver} > /dev/null|| unsupport_os
    DISTRO="el$(rpm --eval %{centos_ver})"
    DEST=/lib64/security/pam-google-web-oauth.so
  fi
else
  unsupport_os
fi

sudo curl -sL $BASE_URL-$DISTRO -o $DEST
cat << EOS
Install Successfly pam-google-web-oauth.

pam module install path: ${DEST}

The rest of the steps are:

1. Write the following in /etc/pam.d/sshd

================================================================================================================================
auth required pam-google-web-oauth.so client_id=%CLIENT_ID% client_secret=%CLIENT_SECRET% user_dir=/opt/pam-google-web-oauth
#@include common-auth # must comment out.
================================================================================================================================


2. Write the following in sshd_config and restart sshd process.

================================================================================================================================
KbdInteractiveAuthentication yes
UsePAM yes
AuthenticationMethods publickey,keyboard-interactive
ChallengeResponseAuthentication yes
================================================================================================================================
EOS
