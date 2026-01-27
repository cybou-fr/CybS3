# CybS3

A command-line S3 compatible object storage browser and file transfer tool, written in pure Swift without AWS SDK dependencies.

## Features

- List buckets and objects
- Upload/download files
- Create/delete objects
- Create buckets
- S3 v4 authentication
- Configuration file support
- Works with any S3-compatible storage

## Installation

### Build from source:

```bash
git clone <repository-url>
cd CybS3
swift build -c release
cp .build/release/cybs3 /usr/local/bin/