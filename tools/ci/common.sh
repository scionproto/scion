usage() {
    echo "Usage: $0: [-d]"
    exit 1
}

while getopts ":d" opt; do
    case "$opt" in
        d)
            DOCKER=true
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
