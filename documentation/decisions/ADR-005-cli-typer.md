# ADR-005 — CLI Python/Typer

Status: Accepted  
Evidência: `recon_ai/cli.py`, `requirements.txt` (`typer==0.27.2`)

## Decisão

Typer como interface. Sem Rich como dependência declarada. Web não é o caminho default.

## Alternativas

Só Bash; Click; TUI.

O PDF citava Rich. Não está em `requirements.txt`.
