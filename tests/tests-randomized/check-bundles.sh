#!/bin/sh

#
# Create an ASN.1 source code project for each line in each of the
# bundles/*.txt files, compile and run that it can be encoded, decoded,
# and fuzzed (if fuzzing is available).
#

set -e

usage() {
    echo "Usage:"
    echo "  $0 -h"
    echo "  $0 [--dirty] -t \"<ASN.1 text defining type T, in string form>\""
    echo "  $0 [--dirty] bundles/<bundle-name.txt> [<line>]"
    echo "Where options are:"
    echo "  -h              Show this help screen"
    echo "  -e <syntax>     Verify a given encoding explicitly (default is ALL)"
    echo "  --asn1c <flag>  Add this flag to asn1c"
    echo "  --dirty         Reuse compile results from the previous run(s)"
    echo "  -t <ASN.1>      Run this particular typel"
    echo "Examples:"
    echo "  $0 -t UTF8String"
    echo "  $0 -t \"T ::= INTEGER (0..1)\""
    echo "  $0 bundles/01-INTEGER-bundle.txt 3"
    exit 1
}

RNDTEMP="${RNDTEMP:-.tmp.random}"

srcdir="${srcdir:-.}"
abs_top_srcdir="${abs_top_srcdir:-`pwd`/../../}"
abs_top_builddir="${abs_top_builddir:-`pwd`/../../}"
abs_builddir="${abs_builddir:-`pwd`}"
export abs_builddir
MAKE="${MAKE:-make}"
FUZZ_TIME="${FUZZ_TIME:-10}"

tests_failed=0
stop_after_failed=1  # We stop after 3 failures.
need_clean_before_bundle=1  # Clean before testing a bundle file
need_clean_before_test=0    # Before each line in a bundle file
encodings=""    # Default is to verify all supported ASN.1 transfer syntaxes
parallelism=1
asn1c_flags=""
testcase=0

make_clean_before_bundle() {
    if [ "${need_clean_before_bundle}" = "1" ] ; then
        (cd "${RNDTEMP}" && Make clean) 2>/dev/null || :
    fi
}

make_clean_before_test() {
    if [ "${need_clean_before_test}" = "1" ] ; then
		exit 1; #TODO:
        Make clean
    else
        # Low resolution file system mtime prevents rapid testing
        # without recompilation. We have to clean at least the most
        # critical portion of the objects. This will reach our objective
        # of fast compile times (since most of skeletons are not recompiled),
        # but won't yield a stale T.o object where newer T.c source exists.
        rm -f T.o libasncodec.a || :
    fi
}

# Get all the type-bearding lines in file and process them individually
verify_asn_types_in_file() {
    filename="$1"
    need_line="$2"
    test "x$filename" != "x" || usage

    make_clean_before_bundle

    echo "# Open [$filename]"
    for mode in syntax full; do
      #if [ "x${mode}" = "xsyntax" ]; then
      #  max_failures=1
      #else
      #  max_failures="${stop_after_failed}"
      #fi

      line=0
      while read asn; do
        line=`expr ${line} + 1`
        if echo "$asn" | sed -e 's/--.*//;' | grep -vi "[A-Z]" > /dev/null; then
            # Ignore lines consisting of just comments.
            continue;
        fi
        if [ "x$need_line" != "x" ] && [ "$need_line" != "$line" ]; then
            # We need a different line.
            continue;
        fi
        verify_asn_type "$mode" "$asn" "in $filename $line" "$line"
        if [ "${tests_failed}" = "${max_failures}" ]; then
            echo "Bail out! STOP after ${tests_failed} failures"
            exit 1
        fi
      done < "$filename"
    done
}

verify_asn_type() {
    mode="$1"
    asn="$2"
    where="$3"
    line="$4"
    shift 3
    test "x$asn" != "x" || usage

    if echo "$asn" | grep -v "::=" > /dev/null; then
        asn="T ::= $asn"
    fi
    echo "# Testing [$asn] ${where}"

    mkdir -p ${RNDTEMP}

    testcase=`expr ${testcase} + 1`
    testlog="${RNDTEMP}/test.$line.log"

    if [ "x${mode}" = "xsyntax" ]; then
        if asn1c_invoke "${RNDTEMP}/test.asn1" "$asn" "$where" -P 1>>${testlog} 2>&1; then
            echo "ok - line:$line mode:${mode}"
            return 0
        else
            echo "not ok - line:${line} mode:${mode} ASN.1 ERROR"
            tests_failed=`expr ${tests_failed} + 1`
            return 1
        fi
    fi

    if !(set -e && cd "${RNDTEMP}" && compile_asn "$asn" "$where" "$line") 1>>${testlog} 2>&1; then
        echo "not ok - line:$line mode:${mode}"
        tail --lines=20 "${testlog}" 1>&2
        tests_failed=`expr ${tests_failed} + 1`
        return 6
    else
        echo "ok - line:$line mode:compile"
        rm -f "${testlog}"
    fi

    # Set default encodings if needed
    [ -z "$encodings" ] && encodings="XER DER UPER OER"

    for enc in $encodings; do
        [ "x$enc" = "x-e" -o -z "$enc" ] && continue;

        testcase=`expr ${testcase} + 1`
        testlog="${RNDTEMP}/test.$line.${enc}.log"
        expected_result=$(get_param ${enc} "" "$asn")
        [ "x$expected_result" != "x" ] && expected_result="# ${expected_result}"

        if (set -e && cd "${RNDTEMP}" && test_asn "$asn" "${where}" "${enc}" "$line") 1>>${testlog} 2>&1; then
            echo "ok - line:$line mode:${mode}, encoding:$enc ${expected_result}"
            rm -f "${testlog}"
        else
            echo "not ok - line:$line mode:${mode}, encoding:${enc} ${expected_result}"
            [ -f "${testlog}" ] && tail -n 20 "${testlog}" 1>&2
        fi
    done
}

Make() {
    ${MAKE} -j "${parallelism}" "$@" || return $?
}

get_param() {
    param="$1"
    default="$2"
    asn="$3"

    "${abs_builddir}/test-param-helper" "${param}" "${default}" "${asn}"
}

# compile_asn "<text>" "<where found>"
# This function is executed in the temporary test directory ${RNDTEMP}.
compile_asn() {
    asn="$1"
    where="$2"
    line="$3"

    if [ "x$CC" = "x" ]; then CCSTR=""; else CCSTR="CC=${CC} "; fi
    echo "cd \"${RNDTEMP}\" && ${CCSTR}CFLAGS=\"${CFLAGS}\" ${MAKE}" > .test-$line-compile

    env > .test-$line-environment
    set > .test-$line-set

    make_clean_before_test

    asn_compile "$asn" "$where" "$line"
    if [ $? -ne 0 ]; then
        echo "Cannot compile ASN.1 $asn"
        return 1
    fi

    rm -f random-test-driver.o
    rm -f random-test-driver
    CFLAGS="${CFLAGS}" Make
    if [ $? -ne 0 ] ; then
        echo "Cannot compile C for $asn in ${RNDTEMP}"
        return 2
    fi
}

# compile_asn "<text>"
# This function is executed in the temporary test directory ${RNDTEMP}.
test_asn() {
    asn="$1"
    where="$2"
    enc="$3"
    enc_arg="-e ${enc}"
    line="$4"

    # Maximum size of the random data
    rmax=`get_param RMAX 128 "$asn"`

    if [ "0${rmax}" -lt 1 ]; then rmax=128; fi


    echo "Checking random data encode-decode for ${enc}"
    round_trip_check_cmd="${ASAN_ENV_FLAGS} ./random-test-driver -s ${rmax} ${enc_arg} -c"
    if eval "$round_trip_check_cmd"; then
        echo "Random test OK"
    else
        echo "($(cat .test-$line-compile) && ${round_trip_check_cmd})" > .test-$line-reproduce;
        echo "RETRY:"; cat .test-$line-reproduce ;
        return 3
    fi

    # If LIBFUZZER_CFLAGS are properly defined, do the fuzz test as well
    if echo "${LIBFUZZER_CFLAGS}" | grep -i "[a-z]" > /dev/null; then

        echo "Generating new random data for ${enc}"
        rm -rf random-data
        cmd="${ASAN_ENV_FLAGS} UBSAN_OPTIONS=print_stacktrace=1"
        cmd="${cmd} ./random-test-driver -s ${rmax} ${enc_arg} -g random-data"
        if eval "$cmd" ; then
            echo "Random data generated OK"
        else
            echo "($(cat .test-$line-compile) && ${round_trip_check_cmd})" > .test-$line-reproduce;
            echo "RETRY:"; cat .test-$line-reproduce ;
            return 4
        fi

        # Do a LibFuzzer based testing
        fuzz_cmd="${ASAN_ENV_FLAGS} UBSAN_OPTIONS=print_stacktrace=1"
        fuzz_cmd="${fuzz_cmd} ./random-test-driver"
        fuzz_cmd="${fuzz_cmd} -timeout=3 -max_total_time=${FUZZ_TIME} -max_len=${rmax}"

        if grep "^fuzz:" Makefile >/dev/null ; then
            echo "No fuzzer defined, skipping fuzzing"
        else
            fuzz_targets=`echo random-data/* | sed -e 's/random-data./fuzz-/g'`
            {
                echo "fuzz: $fuzz_targets"
                echo "fuzz-%: random-data/% random-test-driver"
                echo "	ASN1_DATA_DIR=\$< ${fuzz_cmd} \$<"
            } >> Makefile
        fi

        echo "Recompiling for fuzzing..."
        rm -f random-test-driver.o
        rm -f random-test-driver
        reproduce_make="cd \"${RNDTEMP}\" && ${CCSTR}CFLAGS=\"${LIBFUZZER_CFLAGS} ${CFLAGS}\" ${MAKE}"
        CFLAGS="${LIBFUZZER_CFLAGS} ${CFLAGS}" Make
        if [ $? -ne 0 ]; then
            echo "Recompile failed"
            echo "($(cat .test-$line-compile) && ${round_trip_check_cmd})" > .test-$line-reproduce;
            echo "RETRY:"; cat .test-$line-reproduce ;
            return 4
        fi

        echo "Fuzzing will take a multiple of ${FUZZ_TIME} seconds..."
        CFLAGS="${LIBFUZZER_CFLAGS} ${CFLAGS}" Make fuzz
        if [ $? -ne 0 ]; then
            echo "($(cat .test-$line-compile) && ${round_trip_check_cmd})" > .test-$line-reproduce
            echo "RETRY:"; cat .test-$line-reproduce
            return 5
        fi
    fi
    return 0
}

asn1c_invoke() {
    tmpfile="$1"
    asn="$2"
    where="$3"
    shift 3

    {
    echo "Test DEFINITIONS ::= BEGIN $asn"
    echo "-- ${where}"
    echo "END"
    } > ${tmpfile}
    echo "${abs_top_builddir}/asn1c/asn1c -S ${abs_top_srcdir}/skeletons"
    if "${abs_top_builddir}/asn1c/asn1c" -S "${abs_top_srcdir}/skeletons" \
        ${asn1c_flags} $@ ${tmpfile}
    then
        echo "ASN.1 compiled OK"
    else
        return 1
    fi
}

asn_compile() {
    asn="$1"
    where="$2"
    line="$3"

    # Create "INTEGER (1..2)" from "T ::= INTEGER (1..2) -- RMAX=5"
    short_asn=`echo "$asn" | sed -e 's/ *--.*//;s/RMAX=[0-9]//;'`
    if [ `echo "$short_asn" | grep -c "::="` = 1 ]; then
        short_asn=`echo "$short_asn" | sed -e 's/.*::= *//'`
    fi

    test ! -f Makefile.am   # Protection from accidental clobbering

    asn1c_invoke "test.asn1" "$asn" "$where" "-flink-skeletons"
    if [ $? != 0 ]; then
        return 1
    fi

    rm -f converter-example.c
    ln -sf "../${srcdir}/random-test-driver.c" || cp "../${srcdir}/random-test-driver.c" .
    {
    echo "CFLAGS+= -DASN1_TEXT='$short_asn'";
    echo "ASN_PROGRAM = random-test-driver"
    echo "ASN_PROGRAM_SRCS = random-test-driver.c"
    echo
    echo "include converter-example.mk"
    echo
    echo "all-tests-succeeded: ${abs_top_builddir}/asn1c/asn1c \$(ASN_PROGRAM_SRCS) \$(ASN_MODULE_SRCS) \$(ASN_MODULE_HDRS)"
    echo "	@rm -f \$@"
    echo "	@echo Previous try did not go correctly. To reproduce:"
    echo "	@cat .test-$line-reproduce"
    echo "	@exit 1"
    echo
    } > Makefile
    echo "converter-example.mk -> Makefile"
}

# Make up to four different passes:
#  CFLAGS: | asn1c_flags:
#   -m64   | -fnative-types
#   -m32   | -fnative-types
#   -m64   | -fwide-types
#   -m32   | -fwide-types
# *) Of course, -m64 and -fnative-types are just implied.
test_drive() {
    func="$1"
    shift

    if [ "x${asn1c_flags}" = "x" ] ; then
        # Test for native types and wide types
        asn1c_flags=" " test_drive "${func}" "$@"
        asn1c_flags="-fnative-types" test_drive "${func}" "$@"
        return 0
    fi

    # Can't reuse object code.
    rm -rf ${RNDTEMP}

    echo "# MODE: default"
    # Default (likely 64-bit) mode
    ${func} "$@"

    # 32-bit mode, if available
    if echo "${CFLAGS_M32}" | grep -i '[a-z]' > /dev/null ; then
        echo "# MODE: 32-bit"

        # Can't reuse object code between modes.
        rm -rf ${RNDTEMP}

        # -m32 doesn't support fuzzing (no such library), so we remove fuzzer.
        # -m32 doesn't support leak sanitizing (it hangs), so we remove
        # ASAN_ENV_FLAGS which enable leak check in runtime.
        CFLAGS="${CFLAGS} ${CFLAGS_M32}" CFLAGS_M32="" \
        LIBFUZZER_CFLAGS="" ASAN_ENV_FLAGS="" \
            ${func} "$@"
    fi
}

if echo "$*" | grep ' -- ' > /dev/null; then
    TEST_DRIVER=`echo "$*"  | sed -e 's/ -- .*/ -- /g'`
    args=`echo "$*"  | sed -e 's/.* //g'`
    set "${args}"
else
    TEST_DRIVER=""
fi

# Command line parsing
while :; do
    case "$1" in
        -h) usage ;;
        --asn1c) asn1c_flags="${asn1c_flags} $2"; shift 2; continue ;;
        --bundle)
            shift
            #exec ${TEST_DRIVER} $0 --bundle "$@"

            # Look for the transcript in bundles/NN-*-bundles.txt.log
            # set -x

            base=`basename "$1" | sed -e 's/.txt$//'`
            RNDTEMP=".tmp.${base}"

            #if Make -C "${RNDTEMP}" all-tests-succeeded >/dev/null 2>&1 ; then
            #    echo "Test succeeded before. Not rechecking."
            #    tests_succeeded=1
            #    break
            #fi

            test_drive verify_asn_types_in_file "$@"

            #touch "${RNDTEMP}/all-tests-succeeded"

            break
            ;;
        --dirty)
            need_clean_before_bundle=0
            need_clean_before_test=0
            shift
            continue
            ;;
		--max-failures) stop_after_failed=$2; shift 2; continue;;
        -e) encodings="${encodings} -e $2"; shift 2; continue;;
        -j) parallelism="$1"; shift 2; continue;;
        -t)
            test_drive verify_asn_type "full" "$2" "(command line)" "0" || exit 1 ;;
        "")
            for bundle in `ls -1 ${srcdir}/bundles/*.txt | sort -nr`; do
                test_drive verify_asn_types_in_file "$bundle"
            done
        ;;
        *)
            test_drive verify_asn_types_in_file "$@"
        ;;
    esac
    break
done

echo "# Test Plan"
echo "1..${testcase}"
test $tests_failed -eq 0 && exit 0 || exit 1;
