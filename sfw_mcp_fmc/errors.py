# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: MIT

class FMCClientError(Exception):
    """Base exception for FMC client errors."""


class FMCAuthError(FMCClientError):
    """Authentication / token issues."""


class FMCRequestError(FMCClientError):
    """HTTP/network problems when talking to FMC."""


class InvalidIndicatorError(ValueError):
    """Raised when the indicator string is not a valid IP, CIDR, or FQDN."""
