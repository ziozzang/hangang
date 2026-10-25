"""Bound local planning/release input before parsing it."""
import json
import os
import stat
import tomllib

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 128


def read_text(path, limit=MAX_BYTES):
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError('input must be a bounded regular file')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise ValueError('input exceeds size limit')
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('input must be UTF-8') from None


def json_document(data, **options):
    if len(data) > MAX_BYTES:
        raise ValueError('JSON input exceeds 1 MiB')
    if isinstance(data, str) and len(data.encode('utf-8')) > MAX_BYTES:
        raise ValueError('JSON input exceeds 1 MiB')
    if isinstance(data, bytes):
        try:
            data = data.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError('JSON input must be UTF-8') from None
    depth, quoted, escaped = 0, False, False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError('JSON nesting exceeds 128 containers')
        elif char in ']}':
            depth = max(0, depth - 1)
    return json.loads(data, **options)


def toml_file(path):
    try:
        document = tomllib.loads(read_text(path, 64 * 1024))
    except RecursionError:
        raise ValueError('TOML nesting exceeds limit') from None
    pending = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, (dict, list)):
            if depth >= MAX_DEPTH:
                raise ValueError('TOML nesting exceeds 128 containers')
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1) for child in children)
    return document
