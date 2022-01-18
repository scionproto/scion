
prom ()
{

if [ "$1" = "reload" ]; then
    echo reloading prometheus config files...
    PROMPID=$(systemctl show --property MainPID --value prometheus)
    sudo kill -SIGHUP $PROMPID
fi;

if [ "$1" = "wipe" ]; then
    echo wiping all existing time series...
    curl -X POST -g 'http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]={job="CS"}'
    curl -X POST -g 'http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]={job="BR"}'
    curl -X POST -g 'http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]={job="SD"}'
    curl -X POST -g 'http://localhost:9090/api/v1/admin/tsdb/delete_series?match[]={job="dispatch"}'
fi;

if [ "$1" = "start" ]; then
    echo starting prometheus...
    sudo service prometheus start
fi;

if [ "$1" = "stop" ]; then
    echo stopping prometheus...
    sudo service prometheus stop
fi;
}

if [ "$1" = "" ]; then
    echo type ./prom.sh [command]
    echo commands:
    echo - reload: reload config files
    echo - wipe: wipe all existing time series
    echo - start: start prometheus
    echo - stop: stop prometheus
else
    prom $@
fi;
