import json
import tempfile
import unittest
from pathlib import Path

from recon_ai.ai import _classification_prompt, _routes_prompt
from recon_ai.i18n import (
    CATALOGS,
    DEFAULT_LOCALE,
    I18nError,
    LOCALES,
    display_detail,
    display_name,
    locale_from_env,
    render_checklist,
    require_locale,
    t,
)
from recon_ai.job import JobError, normalize_spec, tool_catalog


class CatalogTests(unittest.TestCase):
    def test_locales_share_every_key(self):
        keys = [set(CATALOGS[locale]) for locale in LOCALES]
        self.assertGreater(len(keys[0]), 200)
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(keys[1], keys[2])

    def test_missing_key_stays_the_key(self):
        self.assertEqual(t("finding.does-not-exist", "en-US"), "finding.does-not-exist")

    def test_invalid_locale_is_an_error(self):
        with self.assertRaises(I18nError):
            require_locale("fr-FR")
        with self.assertRaises(I18nError):
            t("ui.title", "pt")
        with self.assertRaises(I18nError):
            locale_from_env({"RECON_LANG": "es"})
        self.assertEqual(locale_from_env({}), DEFAULT_LOCALE)
        self.assertEqual(locale_from_env({"RECON_LANG": ""}), DEFAULT_LOCALE)

    def test_pt_br_resumo_padding_matches_the_report(self):
        self.assertEqual(t("phase.resumo_live", "pt-BR", n=1), "Hosts vivos             : 1")
        self.assertEqual(t("phase.resumo_401", "pt-BR", n=1), "Hosts 401               : 1")
        self.assertEqual(t("phase.resumo_403", "pt-BR", n=1), "Hosts 403               : 1")
        self.assertEqual(t("phase.resumo_nuclei", "pt-BR", n=1), "Findings Nuclei         : 1")

    def test_classification_prompt_keeps_the_fixture_marker_only_in_pt_br(self):
        finding = {
            "id": 1,
            "severity": "info",
            "template_id": "corr/idor-candidate",
            "name": "Candidato IDOR",
            "matched_at": "https://example.com/a",
        }
        portuguese = _classification_prompt([finding], "pt-BR")
        self.assertIn("Classifique cada finding", portuguese)
        self.assertNotIn("Classifique cada finding", _classification_prompt([finding], "en-US"))
        self.assertNotIn("Classifique cada finding", _routes_prompt("fetch('/api/a');", "pt-BR"))
        self.assertIn("in English", _classification_prompt([finding], "en-US"))
        self.assertIn("en español", _classification_prompt([finding], "es-ES"))


class SpecLocaleTests(unittest.TestCase):
    def test_default_lang_is_pt_br_and_help_changes_with_locale(self):
        spec = normalize_spec({"target": "example.com"})
        self.assertEqual(spec["lang"], "pt-BR")
        spec = normalize_spec({"target": "example.com", "lang": "en-US"})
        self.assertEqual(spec["lang"], "en-US")
        with self.assertRaises(JobError):
            normalize_spec({"target": "example.com", "lang": "fr-FR"})
        portuguese = tool_catalog("pt-BR")
        english = tool_catalog("en-US")
        self.assertTrue(portuguese[0]["help"]["what"].strip())
        self.assertNotEqual(portuguese[0]["help"]["what"], english[0]["help"]["what"])


class RenderTests(unittest.TestCase):
    def test_checklist_json_rerenders_and_txt_stays_in_the_run_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "corr"
            folder.mkdir()
            items = [
                {"key": "checklist.idor_manual", "args": {}},
                {"key": "checklist.crtsh_unresolved", "args": {"n": 1}},
            ]
            (folder / "checklist.json").write_text(json.dumps(items), encoding="utf-8")
            (folder / "checklist.txt").write_text(
                "Confirmar IDOR com duas contas no alvo autorizado.\nNomes só no crt.sh sem DNS: 1\n",
                encoding="utf-8",
            )
            english = render_checklist(tmp, "en-US")
            self.assertIn("Confirm IDOR with two accounts", english[0])
            self.assertIn("Names only in crt.sh without DNS: 1", english[1])
            self.assertIn("Confirmar IDOR", (folder / "checklist.txt").read_text(encoding="utf-8"))

    def test_phase_detail_uses_the_key_or_the_stored_sentence(self):
        self.assertEqual(
            display_detail("em andamento", "phase.running", "", "en-US"),
            "in progress",
        )
        self.assertEqual(
            display_detail("frase antiga", None, None, "en-US"),
            "frase antiga",
        )
        self.assertEqual(
            display_name("corr/idor-candidate", "Candidato IDOR", "en-US"),
            "IDOR candidate",
        )
        self.assertEqual(display_name("nuclei/custom", "Dynamic name", "es-ES"), "Dynamic name")
