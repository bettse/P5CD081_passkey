#!/bin/zsh
# Register and assert with libfido2, an independent CTAP2 stack that sends
# short APDUs, and let it verify the card's signatures.
#
#   libfido2_check.sh            no PIN
#   libfido2_check.sh 1234       also set that PIN first and use it throughout
#
# This wipes the card first (a full card refuses new registrations), and
# setting a PIN changes it again. tools/card_reset.py puts it back.
reader=${READER:-"ACS ACR1555 1S CL Reader(1)"}
pin=$1
dev=$(fido2-token -L | ag -F "$reader" | cut -d: -f1-2)
if [[ -z $dev ]]; then
    echo "no libfido2 device for reader: $reader"
    fido2-token -L
    exit 1
fi
python3 "${0:a:h}/card_reset.py" || exit 1
work=$(mktemp -d -t fido2check)
cd "$work"
fail=0
step() {
    local name=$1; shift
    if "$@" > step.out 2>&1; then
        echo "  ok   $name"
    else
        echo "  FAIL $name"
        sed 's/^/         /' step.out
        fail=1
    fi
}
# fido2-* read the PIN from the terminal, so feed it through expect when one is in play.
withpin() {
    if [[ -z $pin ]]; then
        "$@"
    else
        expect -c "
            log_user 0
            set timeout 60
            spawn $*
            expect {
                -re {[Ee]nter.*PIN.*: } { send \"$pin\r\"; exp_continue }
                eof
            }
            lassign [wait] p s o code
            exit \$code"
    fi
}

echo "device: $dev"
fido2-token -I "$dev" | ag 'version|algorithms|options|maxmsgsiz|pin protocols' | sed 's/^/  /'

if [[ -n $pin ]]; then
    step "set PIN" expect -c "
        log_user 0
        set timeout 30
        spawn fido2-token -S $dev
        expect {
            -re {PIN.*: } { send \"$pin\r\"; exp_continue }
            eof
        }
        lassign [wait] p s o code
        exit \$code"
fi

printf '%s\nlibfido2.example\nalice\n%s\n' "$(openssl rand -base64 32)" "$(printf 'alice-user-id' | base64)" > cred_param
step "register a discoverable ES256 credential" withpin fido2-cred -M -r -i cred_param -o cred_out "$dev" es256
step "libfido2 verifies the attestation" fido2-cred -V -i cred_out -o cred_pubkey.pem es256

printf '%s\nlibfido2.example\n' "$(openssl rand -base64 32)" > assert_param
step "assert without naming the credential" withpin fido2-assert -G -r -i assert_param -o assert_out "$dev" es256
step "libfido2 verifies the assertion" fido2-assert -V -i assert_out cred_pubkey.pem es256

if [[ -n $pin ]]; then
    printf '%s\nlibfido2.example\n' "$(openssl rand -base64 32)" > assert_param2
    step "assert with user verification required" withpin fido2-assert -G -r -v -i assert_param2 -o assert_out2 "$dev" es256
    step "libfido2 verifies that assertion too" fido2-assert -V -v -i assert_out2 cred_pubkey.pem es256
fi

rm -rf "$work"
[[ $fail == 0 ]] && echo PASS || echo FAIL
exit $fail
