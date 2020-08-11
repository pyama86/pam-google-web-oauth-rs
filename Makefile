VERSION  := $(shell git tag | tail -n1 | sed 's/v//g')
build:
	cargo build --release
	strip target/release/libpam_google_web_oauth.so

mv_dist:
	mkdir -p builds/$(DIST)
	mv target/release/libpam_google_web_oauth.so builds/$(DIST)/pam-google-web-oauth.so

clean:
	cargo clean

test:
	cargo test

integration: install
	gcc -o target/pam_test test.c -lpam -lpam_misc

install:
	cp conf/pam-google-web-oauth /etc/pam.d/
	cp target/release/libpam_google_web_oauth.so /lib/x86_64-linux-gnu/security/pam-google-web-oauth.so

ssh_container:
	docker build -f dockerfiles/Dockerfile.sshtest --build-arg CLIENT_ID=$(CLIENT_ID) --build-arg CLIENT_SECRET=$(CLIENT_SECRET) -t ssh .
	docker run --privileged \
	  -v `pwd`:/opt/pam-google-web-oauth \
	  -v $(HOME)/.ssh/id_rsa.pub:/root/.ssh/authorized_keys \
	  -p 10022:22 ssh

run_builder:
	docker build -f dockerfiles/Dockerfile.ubuntu16 -t builder .
	docker run -v `pwd`:/opt/pam-google-web-oauth -w /opt/pam-google-web-oauth -it builder /bin/bash

PRODUCT_CODES=ubuntu16 ubuntu18 centos7 centos8
release_build: clean build mv_dist
release_builds:
	rm -rf builds/*
	for i in $(PRODUCT_CODES); do\
		docker-compose build $$i; \
		docker-compose up $$i; \
	done

github_release: ## Create some distribution packages
	ghr --replace v$(VERSION) builds/


.PHONY: release_major
## release_major: release nke (major)
release_major: releasedeps
	git semv major --bump

.PHONY: release_minor
## release_minor: release nke (minor)
release_minor: releasedeps
	git semv minor --bump

.PHONY: release_patch
## release_patch: release nke (patch)
release_patch: releasedeps
	git semv patch --bump

.PHONY: releasedeps
releasedeps: git-semv

.PHONY: git-semv
git-semv:
	brew tap linyows/git-semv
	brew install git-semv
