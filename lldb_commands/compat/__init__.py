# Glue code here to make stuff work in both python2 and python 3
# In particular:
# - things that are needed for 'command script' usages so multi-line constructs like exceptions won't work
# - things that would otherwise rely on extra installed packages like python-future

# Note: When dslldb.py gets 'command script import'ed, its path gets added to sys.path,
# So later you can do things like:
# from compat import thing_in_compat

# unichr compatibility shim
# In Python 3, use chr instead
# When needed, do:
# from compat import unichr
#
# We need to do this here because you can't squash
# the exception handling into a one-line 'command script'
try:
    _ = unichr(0)
    # We need to actually do this assignment in order to
    # export it in __all__
    unichr = unichr
except NameError:
    unichr = chr


__all__ = [unichr]
