---
title: wp-gpgsign
---

[![Build Status](https://ci.thegeeklab.de/api/badges/thegeeklab/wp-gpgsign/status.svg)](https://ci.thegeeklab.de/repos/thegeeklab/wp-gpgsign)
[![Docker Hub](https://img.shields.io/badge/dockerhub-latest-blue.svg?logo=docker&logoColor=white)](https://hub.docker.com/r/thegeeklab/wp-gpgsign)
[![Quay.io](https://img.shields.io/badge/quay-latest-blue.svg?logo=docker&logoColor=white)](https://quay.io/repository/thegeeklab/wp-gpgsign)
[![Go Report Card](https://goreportcard.com/badge/github.com/thegeeklab/wp-gpgsign)](https://goreportcard.com/report/github.com/thegeeklab/wp-gpgsign)
[![GitHub contributors](https://img.shields.io/github/contributors/thegeeklab/wp-gpgsign)](https://github.com/thegeeklab/wp-gpgsign/graphs/contributors)
[![Source: GitHub](https://img.shields.io/badge/source-github-blue.svg?logo=github&logoColor=white)](https://github.com/thegeeklab/wp-gpgsign)
[![License: Apache-2.0](https://img.shields.io/github/license/thegeeklab/wp-gpgsign)](https://github.com/thegeeklab/wp-gpgsign/blob/main/LICENSE)

Woodpecker CI plugin to sign artifacts with [GnuPG](https://gnupg.org/).

<!-- prettier-ignore-start -->
<!-- spellchecker-disable -->
{{< toc >}}
<!-- spellchecker-enable -->
<!-- prettier-ignore-end -->

## Usage

```YAML
steps:
  - name: gpgsign dist files
    image: quay.io/thegeeklab/wp-gpgsign
    settings:
      key: LS0tLS1CRUdJTi...tLS0tCg==
      passphrase: randomstring
      files:
        - dist/*
```

### Parameters

<!-- prettier-ignore-start -->
<!-- spellchecker-disable -->
{{< propertylist name=wp-gpgsign.data sort=name >}}
<!-- spellchecker-enable -->
<!-- prettier-ignore-end -->

## Build

Build the binary with the following command:

```Shell
make build
```

Build the Container image with the following command:

```Shell
docker build --file Containerfile.multiarch --tag thegeeklab/wp-gpgsign .
```

## Test

```Shell
docker run --rm \
  -e PLUGIN_KEY=LS0tLS1CRUdJTi...tLS0tCg== \
  -e PLUGIN_PASSPHRASE=randomstring \
  -v $(pwd):/build:z \
  -w /build \
  thegeeklab/wp-gpgsign
```
