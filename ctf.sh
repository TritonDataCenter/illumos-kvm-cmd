#!/usr/bin/bash
#
# We need to run ctfconvert on all the .o files in qemu. However, some of these
# .o files contain some snippets that are going to cause ctfconvert to fail. If
# ctfconvert is run with the -i option, it will delete the .o file. This is bad.
# Instead we end up using a temporary file and move over it. 
#
# This file gets invoked from inside the x86-64_softmmu directory, hence the
# extra .. in the path below. That's kind of ugly, and I almost apologize.
#

sh_arg0=$(basename $0)
ctf_bin=$(pwd)/../../../illumos/usr/src/tools/proto/root_i386-nd/opt/onbld/bin/i386/ctfconvert

function fail
{
        local msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$sh_arg0: $msg" >&2
        exit 1
}


[[ $# -eq 1 ]] || fail "missing arguments"

echo "Converting $1"
$ctf_bin -L VERSION -o $1.ctf $1
[[ $? -ne 0 ]] && exit 1
mv $1.ctf $1
exit 0
