"""
AgentShield AI — Detectors Package Export.
"""

from agentshield.threat_detection.detectors.base import BaseDetector
from agentshield.threat_detection.detectors.behavioral import BehavioralAnomalyDetector
from agentshield.threat_detection.detectors.command_analysis import CommandAnalysisDetector
from agentshield.threat_detection.detectors.data_leakage import DataLeakageDetector
from agentshield.threat_detection.detectors.filesystem import FilesystemThreatDetector
from agentshield.threat_detection.detectors.network import NetworkThreatDetector
from agentshield.threat_detection.detectors.prompt_injection import PromptInjectionDetector

DEFAULT_DETECTORS: list[BaseDetector] = [
    PromptInjectionDetector(),
    DataLeakageDetector(),
    FilesystemThreatDetector(),
    CommandAnalysisDetector(),
    NetworkThreatDetector(),
    BehavioralAnomalyDetector(),
]

__all__ = [
    "BaseDetector",
    "PromptInjectionDetector",
    "DataLeakageDetector",
    "FilesystemThreatDetector",
    "CommandAnalysisDetector",
    "NetworkThreatDetector",
    "BehavioralAnomalyDetector",
    "DEFAULT_DETECTORS",
]
