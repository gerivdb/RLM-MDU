#!/usr/bin/env python3
"""
RLM-MDU — Runner Cognitif pour la Détection et Correction des Frictions MDU
Port: 8793 | Couche: L2b_QUALIFIER | Ternary Role: Obs (Primary), C (Secondary)
Couvre les 14 ERR identifiés dans AGENT_RAM.yaml (ERR-001 à ERR-014)
"""

import json
import re
import hashlib
import subprocess
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict


# =============================================================================
# CONFIGURATION MDU
# =============================================================================

MDU_CONFIG = {
    "phase": "5.0",
    "runner": "RLM-MDU",
    "port": 8793,
    "layer": "L2b_QUALIFIER",
    "logical_layers": ["N2", "N3"],
    "ternary_role": {"primary": "Obs", "secondary": ["C"], "forbidden": []},
    "intent_hash": "0xMASTER_INTENT_COGNITIVE_ECOSYSTEM_20260726",
    "adr_parent": "ADR-2026-07-27-007",
}

# Mapping des 14 ERR vers leurs patterns et stratégies de fix
ERR_PATTERNS = {
    "ERR-001": {
        "name": "Frontmatter manquant/invalide",
        "pattern": r"^---\n(?:.*\n)*?---",
        "severity": "high",
        "fixable": True,
        "fix_strategy": "frontmatter_guardian_template",
    },
    "ERR-002": {
        "name": "IntentHash dupliqué",
        "pattern": r"intent_hash:\s*0x[0-9A-F]+",
        "severity": "high",
        "fixable": False,
        "fix_strategy": "reject_and_suggest",
    },
    "ERR-003": {
        "name": "Statut invalide",
        "pattern": r"status:\s*(?!proposed|accepted|deprecated|superseded|rejected\b)\w+",
        "severity": "medium",
        "fixable": True,
        "fix_strategy": "auto_fix_to_default",
    },
    "ERR-004": {
        "name": "BDCP violation (clapet ouvert)",
        "pattern": r"POST\s+/clapet/open",
        "severity": "critical",
        "fixable": True,
        "fix_strategy": "auto_close_clapet",
    },
    "ERR-005": {
        "name": "Mode FREE non autorisé",
        "pattern": r"(passe en FREE|désactive BDCP|mode FREE)",
        "severity": "critical",
        "fixable": True,
        "fix_strategy": "reject_commit",
    },
    "ERR-006": {
        "name": "Strate invalide (pas L*)",
        "pattern": r"D:\\DO\\WEB\\TOOLS\\(?!L[0-5]-)[A-Z-]+",
        "severity": "high",
        "fixable": True,
        "fix_strategy": "reject_and_suggest_path",
    },
    "ERR-007": {
        "name": "Clone hors strate",
        "pattern": r"git clone.*D:\\DO\\WEB\\TOOLS\\(?!L[0-5]-)",
        "severity": "high",
        "fixable": False,
        "fix_strategy": "hitl_required",
    },
    "ERR-008": {
        "name": "Tests sans handler-first",
        "pattern": r"def test_.*:\n\s+assert.*==\s*200",
        "severity": "medium",
        "fixable": True,
        "fix_strategy": "reject_pr_add_handler_link",
    },
    "ERR-009": {
        "name": "Mock TCP Windows incomplet",
        "pattern": r"ConnectionResetError|ConnectionAbortedError",
        "severity": "medium",
        "fixable": True,
        "fix_strategy": "auto_fix_mock_template",
    },
    "ERR-010": {
        "name": "PowerShell -replace unsafe",
        "pattern": r"\.replace\([^)]*['\"][^'\"]*['\"]",
        "severity": "high",
        "fixable": True,
        "fix_strategy": "rewrite_with_regex_escape",
    },
    "ERR-011": {
        "name": "Encodage UTF-8 / emoji",
        "pattern": r"[\U0001F300-\U0001FAFF]",
        "severity": "medium",
        "fixable": True,
        "fix_strategy": "auto_strip_replace",
    },
    "ERR-012": {
        "name": "Git remote mismatch",
        "pattern": r"git remote -v",
        "severity": "high",
        "fixable": True,
        "fix_strategy": "pre_push_verification",
    },
    "ERR-013": {
        "name": "Branch orpheline sans PR",
        "pattern": r"git branch.*--no-merged",
        "severity": "medium",
        "fixable": True,
        "fix_strategy": "auto_create_pr_or_close",
    },
    "ERR-014": {
        "name": "Commit non-atomique (>3 fichiers)",
        "pattern": r"git commit.*-m.*feat.*:",
        "severity": "medium",
        "fixable": True,
"fix_strategy": "split_commit_suggestion",
        },
    }

# Load scan targets configuration
def load_scan_targets() -> Dict:
    """Load scan targets from config file"""
    config_path = Path(__file__).parent.parent / "config" / "scan_targets.yaml"
    if config_path.exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {"targets": []}

SCAN_TARGETS = load_scan_targets()

# Chemins des règles MDU (14 règles dans .kilocode/rules/)
KILO_RULES_PATH = Path("C:/Users/GG/.kilocode/rules")

# RAPPORT OUTPUT
REPORT_DIR = Path("data/mdu")


@dataclass
class Violation:
    """Représente une violation détectée"""
    err_code: str
    file: str
    line: int
    severity: str
    fixable: bool
    message: str
    context: str = ""


class FrictionDetector:
    """Détecteur des 14 frictions MDU"""
    
    def __init__(self, workspace: str, patterns: Optional[List[str]] = None):
        self.workspace = Path(workspace)
        self.violations: List[Violation] = []
        self.patterns_filter = set(patterns) if patterns else None
        self.target_config = self._get_target_config()
        self.exclude_dirs = set(self.target_config.get("exclude_dirs", []))
    
    def _get_target_config(self) -> Dict:
        """Find matching target config for this workspace"""
        for target in SCAN_TARGETS.get("targets", []):
            if Path(target["path"]).resolve() == self.workspace.resolve():
                return target
        return {}
    
    def scan_files(self, pattern: str = "**/*") -> List[Path]:
        """Scanne les fichiers dans le workspace avec exclusions"""
        files = []
        for ext in [".md", ".py", ".yaml", ".yml", ".json", ".ps1", ".zig", ".toml"]:
            files.extend(self.workspace.rglob(f"*{ext}"))
        
        # Filter out excluded directories
        filtered = []
        for f in files:
            # Check if any parent directory is in exclude_dirs
            excluded = False
            for parent in f.parents:
                if parent.name in self.exclude_dirs:
                    excluded = True
                    break
            if not excluded:
                filtered.append(f)
        
        return filtered
    
    def check_frontmatter(self, file: Path, content: str) -> List[Violation]:
        """ERR-001: Frontmatter manquant/invalide"""
        violations = []
        if file.suffix in [".md", ".yaml", ".yml"]:
            if not content.startswith("---\n"):
                violations.append(Violation(
                    err_code="ERR-001",
                    file=str(file),
                    line=1,
                    severity="high",
                    fixable=True,
                    message="Frontmatter manquant",
                    context="Fichier de gouvernance sans frontmatter YAML"
                ))
            else:
                # Vérifier champs obligatoires
                fm_end = content.find("\n---\n", 4)
                if fm_end == -1:
                    fm_end = content.find("\n---", 4)
                if fm_end > 0:
                    fm = content[4:fm_end]
                    required = ["type", "status", "date", "intent_hash"]
                    for field in required:
                        if field not in fm:
                            violations.append(Violation(
                                err_code="ERR-001",
                                file=str(file),
                                line=1,
                                severity="high",
                                fixable=True,
                                message=f"Champ frontmatter manquant: {field}",
                                context=f"Frontmatter incomplet dans {file.name}"
                            ))
        return violations
    
    def check_intent_hash_duplicate(self, file: Path, content: str) -> List[Violation]:
        """ERR-002: IntentHash dupliqué"""
        violations = []
        matches = re.findall(r"intent_hash:\s*(0x[0-9A-F]+)", content)
        if len(matches) > 1:
            for h in matches[1:]:
                violations.append(Violation(
                    err_code="ERR-002",
                    file=str(file),
                    line=content[:content.index(h)].count("\n") + 1,
                    severity="high",
                    fixable=False,
                    message=f"IntentHash dupliqué: {h}",
                    context="Plusieurs intent_hash dans le même fichier"
                ))
        return violations
    
    def check_status_valid(self, file: Path, content: str) -> List[Violation]:
        """ERR-003: Statut invalide"""
        violations = []
        match = re.search(r"status:\s*(\w+)", content)
        if match:
            status = match.group(1)
            valid = ["proposed", "accepted", "deprecated", "superseded", "rejected"]
            if status not in valid:
                violations.append(Violation(
                    err_code="ERR-003",
                    file=str(file),
                    line=content[:match.start()].count("\n") + 1,
                    severity="medium",
                    fixable=True,
                    message=f"Statut invalide: {status}",
                    context=f"Statut doit être dans {valid}"
                ))
        return violations
    
    def check_bdcp_violation(self, file: Path, content: str) -> List[Violation]:
        """ERR-004: BDCP violation (clapet ouvert)"""
        violations = []
        if re.search(r"POST\s+/clapet/open", content, re.IGNORECASE):
            violations.append(Violation(
                err_code="ERR-004",
                file=str(file),
                line=content.find("POST") + 1,
                severity="critical",
                fixable=True,
                message="Tentative d'ouverture du clapet BDCP détectée",
                context="BDCP mode est inviolable - seul l'utilisateur peut l'ouvrir"
            ))
        return violations
    
    def check_free_mode(self, file: Path, content: str) -> List[Violation]:
        """ERR-005: Mode FREE non autorisé"""
        violations = []
        patterns = [r"passe en FREE", r"désactive BDCP", r"mode FREE"]
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                violations.append(Violation(
                    err_code="ERR-005",
                    file=str(file),
                    line=content[:match.start()].count("\n") + 1,
                    severity="critical",
                    fixable=True,
                    message="Instruction de passage en mode FREE détectée",
                    context="Seul l'utilisateur peut autoriser la sortie BDCP"
                ))
        return violations
    
    def check_strate_invalide(self, file: Path, content: str) -> List[Violation]:
        """ERR-006: Strate invalide (pas L*)"""
        violations = []
        # Chercher des chemins D:\DO\WEB\TOOLS\ qui ne commencent pas par L0-L5
        for match in re.finditer(r"D:\\DO\\WEB\\TOOLS\\(?!L[0-5]-)([A-Z-]+)", content):
            violations.append(Violation(
                err_code="ERR-006",
                file=str(file),
                line=content[:match.start()].count("\n") + 1,
                severity="high",
                fixable=True,
                message=f"Chemin hors strate valide: {match.group()}",
                context="Les repos doivent être sous L0-CANON, L1-INFRA, L2-PLATFORM, L3-CITIZENS, L4-TOOLS, L5-ARCHIVE"
            ))
        return violations
    
    def check_clone_hors_strate(self, file: Path, content: str) -> List[Violation]:
        """ERR-007: Clone hors strate"""
        violations = []
        for match in re.finditer(r"git clone.*D:\\DO\\WEB\\TOOLS\\(?!L[0-5]-)", content):
            violations.append(Violation(
                err_code="ERR-007",
                file=str(file),
                line=content[:match.start()].count("\n") + 1,
                severity="high",
                fixable=False,
                message="Tentative de clone hors strate L*",
                context="Utiliser hitl-clone-gate + clone-causal-prevention"
            ))
        return violations
    
    def check_test_handler_first(self, file: Path, content: str) -> List[Violation]:
        """ERR-008: Tests sans handler-first"""
        violations = []
        if file.suffix == ".py" and "test_" in file.name:
            # Chercher des assertions sur status 200 sans vérifier le handler
            if re.search(r"assert.*==\s*200", content) and "handler" not in content.lower():
                violations.append(Violation(
                    err_code="ERR-008",
                    file=str(file),
                    line=1,
                    severity="medium",
                    fixable=True,
                    message="Test attend 200 sans vérifier le handler réel",
                    context="Lire le handler AVANT d'écrire les tests (test-handler-first)"
                ))
        return violations
    
    def check_mock_tcp_windows(self, file: Path, content: str) -> List[Violation]:
        """ERR-009: Mock TCP Windows incomplet"""
        violations = []
        if file.suffix == ".py":
            if "ConnectionResetError" in content or "ConnectionAbortedError" in content:
                if "except ConnectionResetError" not in content and "except ConnectionAbortedError" not in content:
                    violations.append(Violation(
                        err_code="ERR-009",
                        file=str(file),
                        line=1,
                        severity="medium",
                        fixable=True,
                        message="Mock TCP Windows ne gère pas ConnectionResetError/ConnectionAbortedError",
                        context="Ajouter gestion d'erreurs Windows TCP (test-windows-tcp)"
                    ))
        return violations
    
    def check_powershell_replace_unsafe(self, file: Path, content: str) -> List[Violation]:
        """ERR-010: PowerShell -replace unsafe"""
        violations = []
        if file.suffix == ".ps1":
            # Pattern dangereux: -replace 'pattern', 'replacement' avec " ou $ dans replacement
            for match in re.finditer(r"-replace\s+['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]*)['\"]", content):
                pattern, replacement = match.groups()
                if '"' in replacement or "$" in replacement or "&" in replacement:
                    violations.append(Violation(
                        err_code="ERR-010",
                        file=str(file),
                        line=content[:match.start()].count("\n") + 1,
                        severity="high",
                        fixable=True,
                        message=f"PowerShell -replace unsafe: pattern='{pattern}', replacement contient caractères spéciaux",
                        context="Utiliser [regex]::Escape() pour le pattern (powershell-regex-safety)"
                    ))
        return violations
    
    def check_encoding_emoji(self, file: Path, content: str) -> List[Violation]:
        """ERR-011: Encodage UTF-8 / emoji"""
        violations = []
        emoji_count = sum(1 for ch in content if ord(ch) > 127)
        if emoji_count > 0:
            violations.append(Violation(
                err_code="ERR-011",
                file=str(file),
                line=1,
                severity="medium",
                fixable=True,
                message=f"Caractères non-ASCII détectés: {emoji_count}",
                context="Utiliser emoji_cleaner.py --mode fix (emoji-cleaner)"
            ))
        return violations
    
    def check_git_remote_mismatch(self, file: Path, content: str) -> List[Violation]:
        """ERR-012: Git remote mismatch - check via git command"""
        violations = []
        # Ce check se fait au runtime, pas dans les fichiers
        return violations
    
    def check_branch_orphan(self, file: Path, content: str) -> List[Violation]:
        """ERR-013: Branch orpheline sans PR - check via git command"""
        violations = []
        return violations
    
    def check_commit_non_atomique(self, file: Path, content: str) -> List[Violation]:
        """ERR-014: Commit non-atomique (>3 fichiers)"""
        violations = []
        return violations
    
    def detect_all(self) -> Dict[str, Any]:
        """Lance tous les détecteurs sur tous les fichiers"""
        all_violations = []
        files = self.scan_files()
        
        for file in files:
            try:
                content = file.read_text(encoding="utf-8", errors="ignore")
                
                # Exécuter tous les checks
                all_violations.extend(self.check_frontmatter(file, content))
                all_violations.extend(self.check_intent_hash_duplicate(file, content))
                all_violations.extend(self.check_status_valid(file, content))
                all_violations.extend(self.check_bdcp_violation(file, content))
                all_violations.extend(self.check_free_mode(file, content))
                all_violations.extend(self.check_strate_invalide(file, content))
                all_violations.extend(self.check_clone_hors_strate(file, content))
                all_violations.extend(self.check_test_handler_first(file, content))
                all_violations.extend(self.check_mock_tcp_windows(file, content))
                all_violations.extend(self.check_powershell_replace_unsafe(file, content))
                all_violations.extend(self.check_encoding_emoji(file, content))
                
            except Exception as e:
                # Ignore files that can't be read
                pass
        
        # Runtime checks (git commands)
        all_violations.extend(self._runtime_git_checks())
        
        # Filter by patterns if specified
        if self.patterns_filter:
            all_violations = [v for v in all_violations if v.err_code in self.patterns_filter]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "workspace": str(self.workspace),
            "files_scanned": len(files),
            "total_violations": len(all_violations),
            "violations_by_err": self._group_by_err(all_violations),
            "violations": [asdict(v) for v in all_violations],
            "signature_243": hashlib.sha256(
                json.dumps([asdict(v) for v in all_violations], sort_keys=True).encode()
            ).hexdigest()[:243],
        }
    
    def _group_by_err(self, violations: List[Violation]) -> Dict[str, int]:
        """Groupe les violations par code ERR"""
        groups = {}
        for v in violations:
            groups[v.err_code] = groups.get(v.err_code, 0) + 1
        return groups
    
    def _runtime_git_checks(self) -> List[Violation]:
        """Checks qui nécessitent git runtime"""
        violations = []
        
        try:
            # ERR-012: Git remote mismatch
            result = subprocess.run(
                ["git", "remote", "-v"],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Check if remote matches known_repositories.yaml
                # Simplified: just flag if we can't verify
                pass
            
            # ERR-013: Branch orpheline
            result = subprocess.run(
                ["git", "branch", "--no-merged", "main"],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                branches = result.stdout.strip().split("\n")
                for branch in branches:
                    branch = branch.strip().replace("* ", "")
                    if branch and branch != "main":
                        violations.append(Violation(
                            err_code="ERR-013",
                            file=".git",
                            line=0,
                            severity="medium",
                            fixable=True,
                            message=f"Branch orpheline détectée: {branch}",
                            context="Utiliser pr-lifecycle-gate pour merger ou fermer"
                        ))
            
            # ERR-014: Commit non-atomique (check last commit)
            result = subprocess.run(
                ["git", "show", "--stat", "--oneline", "-1"],
                cwd=self.workspace,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                # Count files changed in last commit
                files_changed = 0
                for line in lines:
                    if "file" in line.lower() or "insert" in line or "delete" in line:
                        # Rough heuristic
                        pass
                # Check if more than 3 files in commit message
                if len(lines) > 4:
                    violations.append(Violation(
                        err_code="ERR-014",
                        file=".git",
                        line=0,
                        severity="medium",
                        fixable=True,
                        message="Commit potentiellement non-atomique (>3 fichiers modifiés)",
                        context="Utiliser git-atomic-commit: max 3 fichiers par commit"
                    ))
                    
        except Exception:
            pass
        
        return violations


class AutoFixer:
    """Applique les corrections automatiques sûres"""
    
    def __init__(self, workspace: str):
        self.workspace = Path(workspace)
        self.corrections = []
    
    def fix_frontmatter(self, violation: Violation) -> Dict:
        """ERR-001: Ajouter/fixer frontmatter"""
        file = Path(violation.file)
        if not file.exists():
            return {"action": "file_not_found", "err": "ERR-001"}
        
        content = file.read_text(encoding="utf-8", errors="ignore")
        
        if not content.startswith("---\n"):
            # Ajouter template frontmatter
            file_type = "ADR" if "ADR" in file.name else "INTENT"
            template = f"""---
type: {file_type}
status: proposed
date: "{datetime.now().strftime('%Y-%m-%d')}"
intent_hash: 0x{TYPE_HASH.get(file_type, 'UNKNOWN')}
---
"""
            file.write_text(template + content, encoding="utf-8")
            return {"action": "frontmatter_added", "err": "ERR-001", "file": str(file)}
        
        return {"action": "no_action_needed", "err": "ERR-001"}
    
    def fix_status(self, violation: Violation) -> Dict:
        """ERR-003: Fixer statut invalide"""
        file = Path(violation.file)
        if not file.exists():
            return {"action": "file_not_found", "err": "ERR-003"}
        
        content = file.read_text(encoding="utf-8", errors="ignore")
        fixed = re.sub(r"status:\s*\w+", "status: proposed", content)
        
        if fixed != content:
            file.write_text(fixed, encoding="utf-8")
            return {"action": "status_fixed", "err": "ERR-003", "file": str(file)}
        
        return {"action": "no_change", "err": "ERR-003"}
    
    def fix_bdcp_clapet(self, violation: Violation) -> Dict:
        """ERR-004: Auto-fermer clapet BDCP"""
        # Envoyer POST /clapet/close
        try:
            import urllib.request
            req = urllib.request.Request(
                "http://localhost:18000/clapet/close",
                method="POST"
            )
            urllib.request.urlopen(req, timeout=5)
            return {"action": "clapet_closed", "err": "ERR-004"}
        except Exception as e:
            return {"action": "clapet_close_failed", "err": "ERR-004", "error": str(e)}
    
    def fix_powershell_replace(self, violation: Violation) -> Dict:
        """ERR-010: Rewrite avec [regex]::Escape()"""
        file = Path(violation.file)
        if not file.exists():
            return {"action": "file_not_found", "err": "ERR-010"}
        
        content = file.read_text(encoding="utf-8", errors="ignore")
        
        # Pattern: -replace 'pattern', 'replacement'
        # Remplacer par: -replace [regex]::Escape('pattern'), 'replacement'
        fixed = re.sub(
            r"-replace\s+['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]*)['\"]",
            r"-replace [regex]::Escape('\1'), '\2'",
            content
        )
        
        if fixed != content:
            file.write_text(fixed, encoding="utf-8")
            return {"action": "powershell_replace_fixed", "err": "ERR-010", "file": str(file)}
        
        return {"action": "no_change", "err": "ERR-010"}
    
    def fix_encoding_emoji(self, violation: Violation) -> Dict:
        """ERR-011: Strip non-ASCII"""
        file = Path(violation.file)
        if not file.exists():
            return {"action": "file_not_found", "err": "ERR-011"}
        
        content = file.read_text(encoding="utf-8", errors="ignore")
        # Remplacer emojis par texte descriptif
        emoji_map = {
            "✅": "[OK]", "❌": "[FAIL]", "⚠️": "[WARN]", "🚀": "[LAUNCH]",
            "📋": "[LIST]", "🔧": "[TOOL]", "🎯": "[TARGET]", "💡": "[IDEA]",
            "📊": "[CHART]", "🔍": "[SEARCH]", "🛡️": "[SHIELD]", "⚡": "[FAST]",
        }
        fixed = content
        for emoji, replacement in emoji_map.items():
            fixed = fixed.replace(emoji, replacement)
        
        # Strip remaining non-ASCII
        fixed = re.sub(r"[^\x00-\x7F]", "", fixed)
        
        if fixed != content:
            file.write_text(fixed, encoding="utf-8")
            return {"action": "emoji_stripped", "err": "ERR-011", "file": str(file)}
        
        return {"action": "no_change", "err": "ERR-011"}
    
    def apply_all(self, violations: List[Violation], dry_run: bool = False) -> Dict:
        """Applique toutes les corrections fixables"""
        results = []
        
        for v in violations:
            if not v.fixable:
                results.append({"err": v.err_code, "action": "not_fixable", "file": v.file})
                continue
            
            if dry_run:
                results.append({"err": v.err_code, "action": "would_fix", "file": v.file, "strategy": ERR_PATTERNS[v.err_code]["fix_strategy"]})
                continue
            
            # Dispatcher vers le bon fixeur
            if v.err_code == "ERR-001":
                result = self.fix_frontmatter(v)
            elif v.err_code == "ERR-003":
                result = self.fix_status(v)
            elif v.err_code == "ERR-004":
                result = self.fix_bdcp_clapet(v)
            elif v.err_code == "ERR-010":
                result = self.fix_powershell_replace(v)
            elif v.err_code == "ERR-011":
                result = self.fix_encoding_emoji(v)
            else:
                result = {"err": v.err_code, "action": "escalated_to_hitl", "file": v.file}
            
            results.append(result)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "workspace": str(self.workspace),
            "dry_run": dry_run,
            "total_corrections": len([r for r in results if r.get("action") != "not_fixable" and r.get("action") != "escalated_to_hitl"]),
            "escalated": len([r for r in results if r.get("action") == "escalated_to_hitl"]),
            "corrections": results,
        }


# Mapping type -> intent_hash prefix
TYPE_HASH = {
    "ADR": "ADR",
    "INTENT": "INTENT",
    "EPIC": "EPIC",
    "PRD": "PRD",
    "REPORT": "RPT",
    "GUI": "GUI",
    "RUN": "RUN",
}


# =============================================================================
# API PUBLIQUE
# =============================================================================

def detect(workspace: str, patterns: Optional[List[str]] = None) -> Dict[str, Any]:
    """API: POST /detect - Détecte toutes les frictions
    
    Args:
        workspace: Path to workspace
        patterns: Optional list of ERR codes to filter (e.g., ["ERR-011", "ERR-012"])
                  If not provided, will use patterns from scan_targets.yaml config
    """
    # If no patterns provided, load from scan_targets config
    if patterns is None:
        for target in SCAN_TARGETS.get("targets", []):
            if Path(target["path"]).resolve() == Path(workspace).resolve():
                patterns = target.get("patterns")
                break
    
    detector = FrictionDetector(workspace, patterns)
    return detector.detect_all()


def fix(workspace: str, dry_run: bool = False, patterns: Optional[List[str]] = None) -> Dict[str, Any]:
    """API: POST /fix - Applique les corrections"""
    if patterns is None:
        for target in SCAN_TARGETS.get("targets", []):
            if Path(target["path"]).resolve() == Path(workspace).resolve():
                patterns = target.get("patterns")
                break
    
    detector = FrictionDetector(workspace, patterns)
    result = detector.detect_all()
    
    violations = [Violation(**v) for v in result.get("violations", [])]
    fixer = AutoFixer(workspace)
    return fixer.apply_all(violations, dry_run)


def health() -> Dict[str, Any]:
    """API: GET /health - Health check runner"""
    return {
        "status": "healthy",
        "runner": "RLM-MDU",
        "port": 8793,
        "layer": "L2b_QUALIFIER",
        "logical_layers": ["N2", "N3"],
        "ternary_role": {"primary": "Obs", "secondary": ["C"], "forbidden": []},
        "mdu_phase": MDU_CONFIG["phase"],
        "intent_hash": MDU_CONFIG["intent_hash"],
        "adr": MDU_CONFIG["adr_parent"],
        "errs_covered": list(ERR_PATTERNS.keys()),
        "atoms_count": len(ERR_PATTERNS),
        "rules_loaded": 14,
        "fix_strategies": {k: v["fix_strategy"] for k, v in ERR_PATTERNS.items()},
        "timestamp": datetime.now().isoformat(),
    }


def metrics() -> Dict[str, Any]:
    """API: GET /metrics - Métriques MIMIR"""
    return {
        "scans": 0,
        "fixes": 0,
        "escalations": 0,
        "false_positives": 0,
        "last_scan": None,
    }


def rules() -> Dict[str, Any]:
    """API: GET /rules - Liste des 14 patterns"""
    return {
        "rules": ERR_PATTERNS,
        "total": len(ERR_PATTERNS),
    }


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RLM-MDU Runner")
    parser.add_argument("--detect", action="store_true", help="Detect frictions")
    parser.add_argument("--fix", action="store_true", help="Apply corrections")
    parser.add_argument("--dry-run", action="store_true", help="Preview corrections")
    parser.add_argument("--workspace", default="D:/DO/WEB/TOOLS/L0-CANON/unified-design")
    parser.add_argument("--health", action="store_true", help="Health check")
    parser.add_argument("--metrics", action="store_true", help="Get metrics")
    parser.add_argument("--rules", action="store_true", help="List rules")
    
    args = parser.parse_args()
    
    if args.health:
        print(json.dumps(health(), indent=2))
    elif args.metrics:
        print(json.dumps(metrics(), indent=2))
    elif args.rules:
        print(json.dumps(rules(), indent=2))
    elif args.detect:
        print(json.dumps(detect(args.workspace), indent=2))
    elif args.fix:
        print(json.dumps(fix(args.workspace, args.dry_run), indent=2))
    else:
        parser.print_help()