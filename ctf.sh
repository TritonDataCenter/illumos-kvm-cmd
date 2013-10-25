#!/usr/bin/bash
#
# We need to run ctfconvert on all the .o files in qemu. However, some of these
# .o files contain some snippets that are going to cause ctfconvert to fail. If
# ctfconvert is run with the -i option, it will delete the .o file. This is bad.
# Instead we end up using a temporary file and move over it. 
#

sh_arg0=$(basename $0)

function fail
{
        local msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$sh_arg0: $msg" >&2
        exit 1
}

[[ $# -eq 1 ]] || fail "missing arguments"

# CTFCONVERT may contain a wildcard, so expand it out:
ctfconvert=$(echo ${CTFCONVERT})
[[ -x ${ctfconvert} ]] || fail "could not find ctfconvert at $CTFCONVERT"

echo "Converting $1"
$ctfconvert -L VERSION -o $1.ctf $1
[[ $? -ne 0 ]] && exit 1
mv $1.ctf $1
exit 0
