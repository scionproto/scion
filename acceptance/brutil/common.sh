# This is a base file included/sourced by each border router acceptance test

export TEST_ARTIFACTS_DIR="${ACCEPTANCE_ARTIFACTS:?}/${TEST_NAME}"
DEVINFO_FN=${TEST_ARTIFACTS_DIR}/devinfo.txt

. acceptance/brutil/util.sh

# Following are the functions required by the acceptance framework

# Each test should have its own set_veths function for specific setup
test_setup() {
    set -e
    sudo -p "Setup docker containers and virtual interfaces - [sudo] password for %p: " true
    # Bring up the dispatcher container and add new veth interfaces
    # This approach currently works because the dispatcher binds to 0.0.0.0 address.
    docker-compose -f ${BRUTIL:?}/docker-compose.yml up --detach dispatcher

    set_docker_ns_link

    mkdir -p $TEST_ARTIFACTS_DIR
    set_veths >> $DEVINFO_FN

    cp -r "${BRUTIL:?}/${BRCONF_DIR:?}" "$TEST_ARTIFACTS_DIR/conf"

    sed -i "s/ID = .*$/ID = \"${BRID}\"/g" "$TEST_ARTIFACTS_DIR/conf/brconfig.toml"
    sed -i "s/Path = .*$/Path = \"\/share\/logs\/${BRID}.log\"/g" "$TEST_ARTIFACTS_DIR/conf/brconfig.toml"

    docker-compose -f $BRUTIL/docker-compose.yml up --detach $BRID
}

test_run() {
    set -e
    bin/braccept -borderID "${BRID:?}" -devInfoFilePath "$DEVINFO_FN" \
        -keysDirPath "${BRUTIL:?}/${BRCONF_DIR:?}/keys" "$@"
}

test_teardown() {
    set -e
    sudo -p "Teardown docker containers and virtual interfaces - [sudo] password for %p: " true
    del_veths
    rm -f $DEVINFO_FN
    rm_docker_ns_link
    docker-compose -f $BRUTIL/docker-compose.yml down
}

print_help() {
    PROGRAM="$1"
    echo
	cat <<-_EOF
	    $PROGRAM name
	        return the name of this test
	    $PROGRAM setup
	        execute only the setup phase.
	    $PROGRAM run <args>
	        execute only the run phase (allows passing specific argumented to the test binary).
	    $PROGRAM teardown
	        execute only the teardown phase.
	_EOF
}

do_command() {
    PROGRAM="$1"
    COMMAND="$2"
    TEST_NAME="${3}_acceptance"
    shift 3
    case "$COMMAND" in
        name)
            echo $TEST_NAME ;;
        setup|run|teardown)
            "test_$COMMAND" "$@" ;;
        *) print_help $PROGRAM; exit 1 ;;
    esac
}

