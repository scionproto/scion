if [ $(id -u) = "0" ]; then
    echo "ERROR: Running $0 as root is not supported (and is a bad idea, anyway)"
    exit 1
fi
