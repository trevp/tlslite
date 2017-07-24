# Authors:
#   Hubert Kario (2016)
#
# See the LICENSE file for legal information regarding use of this file.

"""Helper functions for handling lists"""


def getFirstMatching(values, matches):
    """
    Return the first element in :py:obj:`values` that is also in
    :py:obj:`matches`.

    Return None if values is None, empty or no element in values is also in
    matches.

    :type values: collections.abc.Iterable
    :param values: list of items to look through, can be None
    :type matches: collections.abc.Container
    :param matches: list of items to check against
    """
    assert matches is not None
    if not values:
        return None
    return next((i for i in values if i in matches), None)
