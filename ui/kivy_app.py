from __future__ import annotations

from pathlib import Path
from typing import Any

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.spinner import Spinner
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.textinput import TextInput

from core.paths import ensure_data_directories, resource_path
from core.policy_engine import PolicyEngine
from core.quarantine import Quarantine
from core.scanner import Scanner
from ui.about_view import about_content
from ui.localization import LANGUAGES, Translator


class AIFBIAndroidApp(App):
    def build(self) -> TabbedPanel:
        self.data_dirs = ensure_data_directories(Path(self.user_data_dir))
        self.policy = PolicyEngine(self.data_dirs["root"])
        self.scanner = Scanner()
        self.quarantine = Quarantine(self.data_dirs["quarantine"], self.policy)
        self.translator = Translator(str(self.policy.get_settings().get("language", "en-US")))
        self.panel = TabbedPanel(do_default_tab=False)
        self._build_tabs()
        return self.panel

    def _build_tabs(self) -> None:
        t = self.translator.text
        self.panel.clear_widgets()
        dashboard_tab = TabbedPanelItem(text=t("dashboard"))
        dashboard_layout = BoxLayout(orientation="vertical", padding=8, spacing=6)
        self.language = Spinner(
            text=self.translator.language_label(self.translator.language),
            values=[self.translator.language_label(code) for code in LANGUAGES],
            size_hint_y=None,
            height=48,
        )
        self.language.bind(text=self._change_language)
        dashboard_layout.add_widget(self.language)
        mode = self.policy.get_settings().get("shield_mode", "active")
        mode_keys = {"active": "active", "strict": "strict_lockdown", "paused": "paused"}
        self.mode_spinner = Spinner(
            text=t(mode_keys.get(mode, "active")),
            values=tuple(t(key) for key in ("active", "strict_lockdown", "paused")),
            size_hint_y=None,
            height=48,
        )
        self.mode_spinner.bind(text=self._change_mode)
        dashboard_layout.add_widget(self.mode_spinner)
        dashboard_layout.add_widget(Label(text=t("not_available") + " — " + t("desktop_only")))
        dashboard_tab.add_widget(dashboard_layout)
        self.panel.add_widget(dashboard_tab)

        scanner_tab = TabbedPanelItem(text=t("scanner"))
        scanner_layout = BoxLayout(orientation="vertical", padding=8, spacing=6)
        self.text_input = TextInput(hint_text=t("scan_input"), multiline=True, size_hint_y=.35)
        scanner_layout.add_widget(self.text_input)
        scanner_layout.add_widget(self._button(t("scan_text"), self._scan_text))
        scanner_layout.add_widget(self._button(t("scan_file"), lambda: self._open_picker("file")))
        scanner_layout.add_widget(self._button(t("scan_folder"), lambda: self._open_picker("folder")))
        scanner_layout.add_widget(self._button(t("quarantine_selected"), self._quarantine_last))
        self.results = TextInput(readonly=True, multiline=True)
        scanner_layout.add_widget(self.results)
        scanner_tab.add_widget(scanner_layout)
        self.panel.add_widget(scanner_tab)

        logs_tab = TabbedPanelItem(text=t("logs_quarantine"))
        logs_layout = BoxLayout(orientation="vertical", padding=8, spacing=6)
        logs_layout.add_widget(self._button(t("refresh"), self._refresh_quarantine))
        self.audit_view = TextInput(readonly=True, multiline=True, size_hint_y=.4)
        logs_layout.add_widget(self.audit_view)
        self.quarantine_view = TextInput(readonly=True, multiline=True)
        logs_layout.add_widget(self.quarantine_view)
        logs_layout.add_widget(self._button(t("restore"), self._restore_first))
        logs_layout.add_widget(self._button(t("permanently_delete"), self._delete_first))
        logs_tab.add_widget(logs_layout)
        self.panel.add_widget(logs_tab)

        about_tab = TabbedPanelItem(text=t("about"))
        content = about_content(self.translator, resource_path("app_metadata.json"))
        about_text = "\n\n".join([
            f"{content['name']} {content['version']}",
            f"{content['developer_label']}: {content['developer']}",
            str(content["capabilities_title"]),
            *[str(item) for item in content["capabilities"]],
            str(content["disclaimer"]),
        ])
        about_tab.add_widget(TextInput(
            text=about_text,
            readonly=True,
            multiline=True,
            halign="right" if self.translator.is_rtl else "left",
        ))
        self.panel.add_widget(about_tab)
        self._refresh_quarantine()

    @staticmethod
    def _button(text: str, callback: Any) -> Button:
        button = Button(text=text, size_hint_y=None, height=48)
        button.bind(on_release=lambda _button: callback())
        return button

    def _change_language(self, _spinner: Spinner, language: str) -> None:
        code = self.translator.language_code(language)
        if code != self.translator.language:
            self.translator.set_language(code)
            self.policy.update_setting("language", code)
            self._build_tabs()

    def _change_mode(self, _spinner: Spinner, mode: str) -> None:
        mode_code = {
            self.translator.text("active"): "active",
            self.translator.text("strict_lockdown"): "strict",
            self.translator.text("paused"): "paused",
        }.get(mode)
        if mode_code:
            self.policy.update_setting("shield_mode", mode_code)
            self.policy.audit("shield_mode_changed", mode=mode_code)

    def _scan_text(self) -> None:
        self.last_path = None
        self.last_findings = []
        self.results.text = ""
        finding = self.scanner.scan_text(self.text_input.text, self.translator.text("scan_input"))
        rules = ", ".join(self.translator.text(f"rule_{rule}") for rule in finding.matched_rules) or self.translator.text("no_findings")
        self.results.text = (
            f"{self.translator.text('risk_score')}: {finding.risk_score}/100\n"
            f"{self.translator.text('severity')}: {self.translator.text(finding.severity)}\n"
            f"{self.translator.text('matched_rules')}: {rules}\n"
            f"{self.translator.text('recommended_action')}: {self.translator.text(finding.recommended_action)}"
        )
        self.policy.audit("scan_text", risk_score=finding.risk_score, matched_rules=finding.matched_rules)

    def _open_picker(self, mode: str) -> None:
        chooser = FileChooserListView(path=str(Path.home()), dirselect=mode == "folder")
        layout = BoxLayout(orientation="vertical", spacing=6)
        layout.add_widget(chooser)
        popup = Popup(title=self.translator.text("choose_file" if mode == "file" else "choose_folder"), content=layout, size_hint=(.95, .9))

        def scan_selection() -> None:
            selected = chooser.selection[0] if chooser.selection else chooser.path
            popup.dismiss()
            self._scan_path(Path(selected))

        layout.add_widget(self._button(self.translator.text("scan_file" if mode == "file" else "scan_folder"), scan_selection))
        popup.open()

    def _scan_path(self, path: Path) -> None:
        try:
            self.last_path = path
            self.last_findings = self.scanner.scan_path(path)
            self.results.text = "\n\n".join(
                f"{item.target}\n{self.translator.text('risk_score')}: {item.risk_score}/100"
                f"\n{self.translator.text('severity')}: {self.translator.text(item.severity)}"
                f"\n{self.translator.text('matched_rules')}: "
                f"{', '.join(self.translator.text(f'rule_{rule}') for rule in item.matched_rules) or self.translator.text('no_findings')}"
                f"\n{self.translator.text('recommended_action')}: {self.translator.text(item.recommended_action)}"
                for item in self.last_findings
            ) or self.translator.text("no_findings")
            self.policy.audit("scan_path", target=str(path), result_count=len(self.last_findings))
        except (OSError, ValueError) as exc:
            self.results.text = f"{self.translator.text('error')}: {exc}"

    def _quarantine_last(self) -> None:
        findings = getattr(self, "last_findings", [])
        path = getattr(self, "last_path", None)
        if path is None or not path.is_file() or not findings or findings[0].risk_score < 25:
            self.results.text = self.translator.text("select_file_first")
            return
        try:
            self.quarantine.quarantine_path(path, findings[0].to_dict())
            self.results.text = self.translator.text("quarantined_success")
            self._refresh_quarantine()
        except (OSError, ValueError) as exc:
            self.results.text = f"{self.translator.text('error')}: {exc}"

    def _refresh_quarantine(self) -> None:
        entries = self.quarantine.list_items()
        self.audit_view.text = "\n".join(
            f"{item.get('timestamp', '')}  {item.get('event', '')}"
            for item in self.policy.read_audit(100)
        )
        self.quarantine_view.text = "\n".join(
            f"{item['id']} | {Path(item['original_path']).name} | {item['quarantined_at']}" for item in entries
        ) or self.translator.text("no_findings")

    def _restore_first(self) -> None:
        entries = self.quarantine.list_items()
        if entries:
            try:
                self.quarantine.restore(entries[0]["id"])
            except (OSError, KeyError, ValueError) as exc:
                self.results.text = f"{self.translator.text('error')}: {exc}"
        self._refresh_quarantine()

    def _delete_first(self) -> None:
        entries = self.quarantine.list_items()
        if entries:
            try:
                self.quarantine.delete(entries[0]["id"])
            except (OSError, KeyError, ValueError) as exc:
                self.results.text = f"{self.translator.text('error')}: {exc}"
        self._refresh_quarantine()


def run() -> None:
    AIFBIAndroidApp().run()
