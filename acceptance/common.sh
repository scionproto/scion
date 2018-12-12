# Acceptance tests common functions

ia_file() {
    echo ${1:?} | sed -e "s/:/_/g"
}

as_file() {
    ia_file ${1:?} | cut -d '-' -f 2
}
