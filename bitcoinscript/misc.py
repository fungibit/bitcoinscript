"""
Miscellaneous non-bitcoin-related tools used throughout this package.
"""

################################################################################

# source: http://stackoverflow.com/a/22729414
class classproperty(object):
    """ @classmethod+@property """
    def __init__(self, f):
        self.f = classmethod(f)
    def __get__(self, *a):
        return self.f.__get__(*a)()

################################################################################
