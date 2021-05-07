"""Test DID web routes."""

# pylint: disable=redefined-outer-name

import pytest
from asynctest import mock as async_mock
from pydid import DIDDocument

from ...admin.request_context import AdminRequestContext
