#!/bin/sh

set -eu

# The pinned Semgrep wheel ships a native core and its complete shared-library
# closure together. Keep that closure out of Python: LD_LIBRARY_PATH would be
# inherited when Semgrep re-enters pysemgrep and can preload the wheel's libm
# into the host interpreter. The glibc loader's --library-path applies only to
# this one native invocation and is not inherited by later processes.
unset LD_LIBRARY_PATH
unset LD_PRELOAD

case "$0" in
  /*) ;;
  *)
    echo "Semgrep core loader requires an absolute invocation path." >&2
    exit 126
    ;;
esac

loader_directory="$(CDPATH= cd -- "${0%/*}" && pwd -P)"
native_executable="${loader_directory}/semgrep-core.native"
library_directory="${loader_directory}/libs"
dynamic_loader="/lib64/ld-linux-x86-64.so.2"

if [ ! -f "${native_executable}" ] || [ -L "${native_executable}" ]; then
  echo "Semgrep core loader cannot find its verified native executable." >&2
  exit 126
fi
if [ ! -d "${library_directory}" ] || [ -L "${library_directory}" ]; then
  echo "Semgrep core loader cannot find its verified library directory." >&2
  exit 126
fi
if [ ! -x "${dynamic_loader}" ]; then
  echo "Semgrep core loader cannot find the Linux x86-64 dynamic loader." >&2
  exit 126
fi

exec "${dynamic_loader}" \
  --library-path "${library_directory}" \
  --argv0 semgrep-core \
  "${native_executable}" \
  "$@"
