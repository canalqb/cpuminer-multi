#!/bin/sh

# Gera o configure a partir dos fontes do projeto.
# Requer autoconf 2.5x+ e automake 1.7+.

set -e

# Tenta o caminho moderno e robusto (autoreconf) primeiro.
# Se não estiver disponível, cai para a sequência manual clássica.
if command -v autoreconf >/dev/null 2>&1; then
    autoreconf -fi
else
    echo "autoreconf não encontrado; usando sequência manual." >&2
    aclocal
    autoheader
    automake --gnu --add-missing --copy
    autoconf
fi
