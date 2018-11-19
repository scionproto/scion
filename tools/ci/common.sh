usage() {
    echo "Usage: $0: [-d] [-a]"
    exit 1
}

while getopts ":d :a" opt; do
    case "$opt" in
        d)
            DOCKER_BE="-d"
        ;;
        a)
            ALL=true
        ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
        ;;
        *)
            usage
        ;;
    esac
done
shift $((OPTIND-1))
