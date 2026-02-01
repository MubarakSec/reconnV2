"""Learning module for ML-based vulnerability prioritization.

This module provides machine learning capabilities for
learning from labeled scan results and prioritizing findings.

Note: Requires scikit-learn to be installed for full functionality.
"""

from recon_cli.learning.collector import DatasetStore, HostFeatures

# LearningModel requires sklearn, so import conditionally
try:
    from recon_cli.learning.model import LearningModel, SKLEARN_AVAILABLE
except ImportError:
    LearningModel = None  # type: ignore
    SKLEARN_AVAILABLE = False

__all__ = [
    "DatasetStore",
    "HostFeatures",
    "LearningModel",
    "SKLEARN_AVAILABLE",
]

