
# Stdlib
import configparser


def create_zlog_file(zlog_path, serv_name):
    """
    Generate the zlog configuration file for all logging levels
    :param str zlog_path: the path of the generated zlog configuration file.
    :param str serv_name: name of the SCION service instance this file is for
    """
    config = configparser.ConfigParser(allow_no_value=True, delimiters=' ',
                                       interpolation=None,
                                       )
    config.optionxform = str
    config.add_section('global')
    config['global']['default format'] = '= "%d(%F %T).%us%d(%z)' \
                                         ' [%V] (%p:%c:%F:%L) %m%n"'
    config['global']['file perms'] = '= 644'

    config.add_section('rules')
    config['rules']['default.*'] = '>stdout'
    for level in ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL']:
        config['rules']['libhsr.{}'.format(level)] = \
            '"logs/{}.libhsr.{}", 10MB*2'.format(serv_name, level)
    with open(zlog_path, 'w') as zlogfile:
        config.write(zlogfile, space_around_delimiters=False)
    return
