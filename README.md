# HTTP-scan

## Basic overview

Tool to test the state of security for websites on the public internet using [Mozilla HTTP Observatory API](https://github.com/mozilla/http-observatory/blob/master/httpobs/docs/api.md). The output is the test data in JSON format for each website in the file.

## Status

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-brightgreen.svg)](https://www.gnu.org/licenses/gpl-3.0)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/JavDomGom/HTTP-scan)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

## Logging

You can configure the following enviroment variables to logging:

```bash
export LOG_PATH="/path/to/write/log/file/"
export TRACE_LEVEL="DEBUG"
```

By default:

```
LOG_PATH="log"
TRACE_LEVEL="INFO"
```

## How to run

```bash
~$ python3 main.py -f file.txt
```

<p align="center"><img src="https://github.com/JavDomGom/HTTP-scan/blob/main/img/http-scan_example.gif"></p>

## Questions

If you have questions, please email inquiries to JavDomGom@protonmail.com.

If you don't understand the documentation, please tell us, so we can explain it better. The general idea is: if you need to ask for help, then something needs to be fixed so you (and others) don't need to ask for help. Asking questions helps us to know what needs to be documented, described, and/or fixed.
