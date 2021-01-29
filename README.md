# HTTP-scan

Tool to test the state of security for websites on the public internet.

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
