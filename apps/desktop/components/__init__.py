"""
AgentShield AI — Reusable UI Components (Phase 2).

All widgets imported here for convenience:
    from apps.desktop.components import StatCard, StatusBadge, ...
"""
from apps.desktop.components.stat_card    import StatCard
from apps.desktop.components.status_badge import StatusBadge, DecisionBadge, RiskBadge
from apps.desktop.components.data_table   import DataTable
from apps.desktop.components.page_header  import PageHeader
from apps.desktop.components.empty_state  import EmptyState
from apps.desktop.components.mini_chart   import BarChartWidget, DonutChartWidget

__all__ = [
    "StatCard", "StatusBadge", "DecisionBadge", "RiskBadge",
    "DataTable", "PageHeader", "EmptyState",
    "BarChartWidget", "DonutChartWidget",
]
