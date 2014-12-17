#20110311
#Jan Mojzis
#Public domain.


try:
	from distutils.sysconfig import get_config_var
except ImportError:
	#XXX - python1.5
	print ("gcc -shared -ldl -lm")
else:
	print ('%s %s %s' % (
        	get_config_var('LDSHARED'),
        	get_config_var('LIBS'),
        	get_config_var('SYSLIBS')
	))
