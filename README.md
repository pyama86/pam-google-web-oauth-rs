# pam-google-web-oauth
## Description
pam-google-web-oauth is ssh authentication software.
this provides you multi-factor authentication.


![demo](https://github.com/pyama86/google-web-oauth/blob/master/media/demo.gif)
## Usage

### Install Script
```
$ curl -s https://pam-google-web-oauth.lolipop.io/install.sh | bash -
```

### Manualy install

1. Get the oAuth client ID on google.
2. set binary.
   - debian: /lib/x86_64-linux-gnu/security/pam-google-web-oauth.so
   - centos: /lib64/security/pam-google-web-oauth.so

3. Write the following in /etc/pam.d/sshd
```
auth required pam-google-web-oauth.so client_id=%CLIENT_ID% client_secret=%CLIENT_SECRET% user_dir=/opt/pam-google-web-oauth
#@include common-auth # must comment out.
```

4. Write the following in sshd_config and restart sshd process.

```
KbdInteractiveAuthentication yes
UsePAM yes
AuthenticationMethods publickey,keyboard-interactive
ChallengeResponseAuthentication yes
```

## Contribution

1. Fork ([https://github.com/pyama86/google-web-oauth/fork](https://github.com/pyama86/google-web-oauth/fork))
1. Create a feature branch
1. Commit your changes
1. Rebase your local changes against the master branch
1. Run test suite with the `go test ./...` command and confirm that it passes
1. Run `gofmt -s`
1. Create a new Pull Request

## Author

[pyama86](https://github.com/pyama86)
