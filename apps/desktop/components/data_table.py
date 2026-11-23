"""Reusable filterable data table with badge support."""
from __future__ import annotations
from typing import Any, Callable, Optional
from PySide6.QtCore import Qt, QSortFilterProxyModel, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QTableView,
    QHeaderView, QLabel, QComboBox, QPushButton, QAbstractItemView,
)
from apps.desktop.themes.design_tokens import T


class _TableModel(QAbstractTableModel):
    def __init__(self, headers: list[str], rows: list[list[Any]]):
        super().__init__()
        self._headers = headers
        self._rows    = rows

    def rowCount(self, parent=QModelIndex()): return len(self._rows)
    def columnCount(self, parent=QModelIndex()): return len(self._headers)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return str(self._rows[index.row()][index.column()])
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def set_rows(self, rows: list[list[Any]]):
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def get_row(self, row: int) -> list[Any]:
        return self._rows[row]


class DataTable(QWidget):
    """
    A searchable, filterable table widget backed by Qt Model/View.

    Parameters
    ----------
    headers:        Column header strings.
    rows:           2D list of plain-text values.
    filter_col:     Column index to apply the combo filter on (optional).
    filter_options: Options for the combo filter ["All", ...].
    on_select:      Callback(row_data: list) called when a row is clicked.
    search_cols:    Column indices searched when user types (defaults to all).
    """

    def __init__(
        self,
        headers: list[str],
        rows: list[list[Any]],
        filter_col: int = -1,
        filter_options: Optional[list[str]] = None,
        on_select: Optional[Callable[[list[Any]], None]] = None,
        search_cols: Optional[list[int]] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._filter_col   = filter_col
        self._filter_opts  = filter_options or []
        self._on_select    = on_select
        self._search_cols  = search_cols
        self._all_rows     = rows[:]
        self._headers      = headers

        self._model = _TableModel(headers, rows)
        self._proxy = QSortFilterProxyModel()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)  # search all columns

        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(T.SP_2)

        # ── Toolbar ──────────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(T.SP_2)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search…")
        self._search.textChanged.connect(self._apply_filter)
        self._search.setMaximumWidth(280)
        toolbar.addWidget(self._search)

        if self._filter_opts:
            self._combo = QComboBox()
            self._combo.addItems(self._filter_opts)
            self._combo.currentTextChanged.connect(self._apply_filter)
            self._combo.setMaximumWidth(180)
            toolbar.addWidget(self._combo)

        toolbar.addStretch()

        self._count_lbl = QLabel()
        self._count_lbl.setStyleSheet(f"color:{T.TEXT_MUTED}; font-size:{T.FS_SM}px;")
        toolbar.addWidget(self._count_lbl)

        root.addLayout(toolbar)

        # ── Table ─────────────────────────────────────────────────────────────
        self._view = QTableView()
        self._view.setModel(self._proxy)
        self._view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._view.setAlternatingRowColors(True)
        self._view.setShowGrid(False)
        self._view.verticalHeader().setVisible(False)
        self._view.horizontalHeader().setStretchLastSection(True)
        self._view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._view.setStyleSheet(
            f"QTableView {{ background:{T.SURFACE}; border:1px solid {T.BORDER};"
            f"  border-radius:{T.R_MD}px; outline:none; }}"
            f"QTableView::item:alternate {{ background:{T.SURFACE_ALT}; }}"
            f"QTableView::item:selected {{ background:{T.PRIMARY_LIGHT}; color:{T.TEXT}; }}"
        )
        self._view.clicked.connect(self._row_clicked)
        root.addWidget(self._view)
        self._update_count()

    def _apply_filter(self):
        text = self._search.text().strip()
        combo_val = ""
        if hasattr(self, "_combo"):
            combo_val = self._combo.currentText()

        if self._filter_col >= 0 and combo_val and combo_val != "All":
            filtered = [
                r for r in self._all_rows
                if combo_val.lower() in str(r[self._filter_col]).lower()
            ]
        else:
            filtered = self._all_rows[:]

        if text:
            cols = self._search_cols or list(range(len(self._headers)))
            filtered = [
                r for r in filtered
                if any(text.lower() in str(r[c]).lower() for c in cols if c < len(r))
            ]

        self._model.set_rows(filtered)
        self._update_count()

    def _update_count(self):
        total   = len(self._all_rows)
        showing = self._model.rowCount()
        self._count_lbl.setText(f"{showing} of {total}")

    def _row_clicked(self, index):
        if self._on_select:
            src = self._proxy.mapToSource(index)
            row_data = self._model.get_row(src.row())
            self._on_select(row_data)

    def set_rows(self, rows: list[list[Any]]):
        self._all_rows = rows[:]
        self._model.set_rows(rows)
        self._update_count()

    def get_view(self) -> QTableView:
        return self._view
