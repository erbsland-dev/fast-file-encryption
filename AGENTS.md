# Contributor Guide

## Requirements

- This library requires Python 3.11+ and the `cryptography` package.

## Code Style

- Before committing any changes, run `black` with `--line-length 120` to format the file(s).

## Project structure

- All the relevant library files are in `src/fast_file_encryption`.
- All unit tests are in `tests`.
- The documentation is in Sphinx format and in `docs`.

## Pre-Checks

- The `coverage`, `pyte` and `pyright` should be pre-installed in the environment.

## Run Unit Rests

- Run all unit tests by executing `pytest` in the document root.