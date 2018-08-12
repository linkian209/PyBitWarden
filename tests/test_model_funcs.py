"""tests.test_model_funcs

This module tests the helper functions for the models of this app.

Attributes:
    UUID_REGEX: A regular expression for testing valid UUIDS
"""
import pytest # noqa
import re
import time

import models.funcs as test_funcs


UUID_REGEX = '\A[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\Z' # noqa


def testGenerateSecureUUIDMakesValidUUID():
    """
    This test will validate that the function generates a valid UUID. The
    version number should be 1 to 5.
    """
    test_uuid = test_funcs.generateSecureUUID()

    test_regex = re.compile(UUID_REGEX)

    test_matches = test_regex.match(test_uuid)

    assert test_matches is not None


def testGenerateSecureUUIDMakesRandomUUIDs():
    """
    This test verifies that the function will generate unique UUIDs.
    """
    test_uuids = [test_funcs.generateSecureUUID() for x in range(100)]

    assert len(test_uuids) is len(set(test_uuids))


def testConstantTimeCompareWorks():
    """
    This test makes sure that constantTimeCompare correctly compares.
    """
    test_val1 = 'test'
    test_val2 = 'test'
    test_val3 = 't3st'

    assert test_funcs.constantTimeCompare(test_val1, test_val2)
    assert not test_funcs.constantTimeCompare(test_val1, test_val3)


def testConstantTimeCompareIsConstantTime():
    """
    This test will verify that it takes the same amount of time to compare
    the two values regardless of any differences with respect to the default
    string compare
    """
    correct_val = 'test_val'
    test_val1 = 'Test_val'
    test_val2 = 'tesT_val'
    test_val3 = 'test_vAl'
    time_margin = .000006

    startTime = time.time()
    test_funcs.constantTimeCompare(correct_val, correct_val)
    base_line = time.time() - startTime

    startTime = time.time()
    test_funcs.constantTimeCompare(correct_val, test_val1)
    test_time = time.time() - startTime
    assert abs(test_time - base_line) <= time_margin

    startTime = time.time()
    test_funcs.constantTimeCompare(correct_val, test_val2)
    test_time = time.time() - startTime
    assert abs(test_time - base_line) <= time_margin

    startTime = time.time()
    test_funcs.constantTimeCompare(correct_val, test_val3)
    test_time = time.time() - startTime
    assert abs(test_time - base_line) <= time_margin
