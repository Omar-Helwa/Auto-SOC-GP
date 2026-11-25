"""SPL (Splunk search) support at the edges of Blue.

Sigma stays the internal model. SPL comes in through ``parser`` + ``convert``
(SPL -> Sigma dict) and goes out through ``render`` (Sigma dict -> SPL text).
Only a plain-search subset is supported; everything else is refused clearly.
"""

from .convert import (  # noqa: F401
    convert_text,
    describe_conditions,
    sigma_rule_to_spl,
    spl_to_sigma_rule,
)
from .errors import SplError, SplUnsupported  # noqa: F401
