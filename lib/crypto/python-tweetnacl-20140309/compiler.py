#20110311
#Jan Mojzis
#Public domain.

try:
	from distutils.sysconfig import get_config_var, get_python_inc
except ImportError:
	#XXX - python1.5
	import sys
	print("gcc -g -O2 -fPIC -DPIC -I/usr/include/python%s -I/usr/local/include/python%s" % (sys.version[0:3], sys.version[0:3]))
else:
	try:
        	platform_inc=get_python_inc(plat_specific=True)
	except:
        	platform_inc=get_python_inc(plat_specific=1)

	print ('%s %s -fPIC -DPIC -I%s -I%s' % (
        	get_config_var('CC'),
        	get_config_var('CFLAGS'),
        	get_python_inc(),
        	platform_inc
	))
