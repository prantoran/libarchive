#!/bin/bash

export SFXDIR=$(pwd)
echo "Current work dir: ${SFXDIR}"
export FILE_PREFIX=encmt
export FILE_EXT=exe
export ARCHIVETYPE=rar
sudo rm -r out/$FILE_PREFIX
mkdir -p out/$FILE_PREFIX
make build_parse_${ARCHIVETYPE} \
    && cd out/${FILE_PREFIX} \
    && cp ${SFXDIR}/${ARCHIVETYPE}/test_samples/${FILE_PREFIX}.${FILE_EXT} ${FILE_PREFIX}.${FILE_EXT} \
    && cp ${SFXDIR}/bin/parse_${ARCHIVETYPE}.o parse_${ARCHIVETYPE}.o \
    && ./parse_${ARCHIVETYPE}.o ${FILE_PREFIX}.${FILE_EXT}
cd ${SFXDIR}
unset FILE_PREFIX
unset FILE_EXT
unset SFXDIR
unset ARCHIVETYPE