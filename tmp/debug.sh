#!/bin/bash

export SFXDIR=$(pwd)
echo "Current work dir: ${SFXDIR}"
export FILE_PREFIX=rar3_cmt
export FILE_SUFFIX=_gdb
export FILE_EXT=rar
export ARCHIVETYPE=rar
export CURWD=out/${FILE_PREFIX}${FILE_SUFFIX}
sudo rm -r ${CURWD}
mkdir -p ${CURWD}
make build_parse_${ARCHIVETYPE} \
    && cd ${CURWD} \
    && cp ${SFXDIR}/${ARCHIVETYPE}/test_samples/${FILE_PREFIX}.${FILE_EXT} ${FILE_PREFIX}.${FILE_EXT} \
    && cp ${SFXDIR}/bin/parse_${ARCHIVETYPE}.o parse_${ARCHIVETYPE}.o \
    && gdb --args ./parse_${ARCHIVETYPE}.o ${FILE_PREFIX}.${FILE_EXT}
cd ${SFXDIR}
unset FILE_PREFIX
unset FILE_SUFFIX
unset CURWD
unset FILE_EXT
unset SFXDIR
unset ARCHIVETYPE