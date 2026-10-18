#!/usr/bin/env python3
"""SUID Scanner: ferramenta educacional para auditoria de arquivos SUID no Linux."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

APP_NAME = "SUID Scanner"
VERSION = "1.0.0"
console = Console()

# Classificações heurísticas para priorizar a revisão manual.
# Elas NÃO confirmam vulnerabilidade nem substituem a validação do contexto.
CATALOG: dict[str, dict[str, str]] = {
    "bash": {"risk": "CRÍTICO", "category": "Shell", "impact": "Um shell com SUID pode permitir ações com privilégios elevados, dependendo do comportamento da versão e do contexto.", "recommendation": "Verifique a necessidade do SUID e remova-o se não for explicitamente necessário."},
    "sh": {"risk": "CRÍTICO", "category": "Shell", "impact": "Um interpretador de comandos privilegiado pode ampliar o impacto de uma execução.", "recommendation": "Confirme a finalidade do SUID e remova-o se desnecessário."},
    "dash": {"risk": "ALTO", "category": "Shell", "impact": "Interpretador de comandos; o risco depende do comportamento e da configuração.", "recommendation": "Revise a necessidade operacional e os privilégios."},
    "zsh": {"risk": "ALTO", "category": "Shell", "impact": "Um shell privilegiado pode ampliar o impacto de uma execução.", "recommendation": "Revise a necessidade operacional e os privilégios."},
    "find": {"risk": "ALTO", "category": "Utilitário", "impact": "Algumas formas de execução podem permitir ações com privilégios elevados.", "recommendation": "Remova o SUID se não houver necessidade documentada."},
    "vim": {"risk": "ALTO", "category": "Editor", "impact": "Editores podem oferecer recursos para executar comandos ou alterar arquivos.", "recommendation": "Evite SUID em editores; revise a necessidade."},
    "nano": {"risk": "MÉDIO", "category": "Editor", "impact": "Um editor privilegiado pode expor arquivos sensíveis a alterações.", "recommendation": "Revise a necessidade e restrinja os privilégios."},
    "less": {"risk": "MÉDIO", "category": "Pager", "impact": "Algumas configurações e recursos podem permitir ações externas.", "recommendation": "Revise a necessidade do SUID e o contexto de execução."},
    "more": {"risk": "MÉDIO", "category": "Pager", "impact": "O comportamento interativo pode ampliar a superfície de risco.", "recommendation": "Revise a necessidade do SUID."},
    "awk": {"risk": "ALTO", "category": "Interpretador", "impact": "Interpretadores podem executar operações e comandos dependendo do contexto.", "recommendation": "Evite SUID em interpretadores de uso geral."},
    "perl": {"risk": "CRÍTICO", "category": "Interpretador", "impact": "Um interpretador privilegiado pode executar operações arbitrárias com os privilégios efetivos disponíveis.", "recommendation": "Remova o SUID se não for estritamente necessário."},
    "python": {"risk": "CRÍTICO", "category": "Interpretador", "impact": "Um interpretador privilegiado pode executar operações arbitrárias com os privilégios efetivos disponíveis.", "recommendation": "Remova o SUID se não for estritamente necessário."},
    "python2": {"risk": "CRÍTICO", "category": "Interpretador", "impact": "Um interpretador privilegiado pode executar operações arbitrárias com os privilégios efetivos disponíveis.", "recommendation": "Remova o SUID se não for estritamente necessário."},
    "python3": {"risk": "CRÍTICO", "category": "Interpretador", "impact": "Um interpretador privilegiado pode executar operações arbitrárias com os privilégios efetivos disponíveis.", "recommendation": "Remova o SUID se não for estritamente necessário."},
    "ruby": {"risk": "ALTO", "category": "Interpretador", "impact": "Um interpretador privilegiado pode executar operações que merecem revisão.", "recommendation": "Revise e remova o SUID se desnecessário."},
    "lua": {"risk": "ALTO", "category": "Interpretador", "impact": "Um interpretador privilegiado pode executar operações que merecem revisão.", "recommendation": "Revise e remova o SUID se desnecessário."},
    "tar": {"risk": "ALTO", "category": "Arquivos", "impact": "Recursos de arquivamento podem ter implicações de segurança em contexto privilegiado.", "recommendation": "Revise a necessidade e a configuração do binário."},
    "cp": {"risk": "ALTO", "category": "Arquivos", "impact": "Cópias privilegiadas podem expor ou sobrescrever arquivos sensíveis.", "recommendation": "Remova o SUID se não for necessário."},
    "mv": {"risk": "ALTO", "category": "Arquivos", "impact": "Movimentação privilegiada pode afetar arquivos sensíveis.", "recommendation": "Remova o SUID se não for necessário."},
    "tee": {"risk": "ALTO", "category": "Escrita de arquivos", "impact": "Escritas privilegiadas podem alterar arquivos sensíveis.", "recommendation": "Revise a necessidade e remova o SUID se desnecessário."},
    "wget": {"risk": "ALTO", "category": "Rede", "impact": "Transferências em contexto privilegiado podem trazer riscos adicionais.", "recommendation": "Evite SUID em ferramentas de transferência de uso geral."},
    "curl": {"risk": "ALTO", "category": "Rede", "impact": "Transferências em contexto privilegiado podem trazer riscos adicionais.", "recommendation": "Evite SUID em ferramentas de transferência de uso geral."},
    "nmap": {"risk": "ALTO", "category": "Rede", "impact": "Recursos avançados ou interativos podem ampliar a superfície de risco.", "recommendation": "Revise a versão, a configuração e a necessidade do SUID."},
    "env": {"risk": "ALTO", "category": "Ambiente", "impact": "Manipulação do ambiente de execução pode ter implicações em contexto privilegiado.", "recommendation": "Revise a necessidade do SUID."},
    "docker": {"risk": "CRÍTICO", "category": "Contêineres", "impact": "Acesso ao mecanismo Docker pode, dependendo da configuração, equivaler a controle amplo do host.", "recommendation": "Revise permissões, grupos e configuração do serviço Docker."},
}

RISK_STYLES = {
    "CRÍTICO": "bold white on red",
    "ALTO": "bold red",
    "MÉDIO": "bold yellow",
    "BAIXO": "bold green",
    "REVISAR": "bold cyan",
}


def owner_name(uid: int) -> str:
    """Retorna o nome do proprietário ou o UID caso não esteja cadastrado."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (ImportError, KeyError, OSError):
        return str(uid)


def group_name(gid: int) -> str:
    """Retorna o nome do grupo ou o GID caso não esteja cadastrado."""
    try:
        import grp
        return grp.getgrgid(gid).gr_name
    except (ImportError, KeyError, OSError):
        return str(gid)


def classify_file(path: str) -> dict[str, str]:
    """Classifica um caminho com base no nome do arquivo, sem afirmar que há falha."""
    name = os.path.basename(path)
    entry = CATALOG.get(name)
    if entry:
        return {
            "risk": entry["risk"],
            "category": entry["category"],
            "impact": entry["impact"],
            "recommendation": entry["recommendation"],
        }
    return {
        "risk": "REVISAR",
        "category": "Não catalogado",
        "impact": "O nome não consta no catálogo local; o risco não foi determinado.",
        "recommendation": "Verifique a origem, o proprietário, as permissões e a necessidade do SUID manualmente.",
    }


def scan_suid_files(root_path: str) -> tuple[list[dict[str, Any]], int, str | None]:
    """Localiza arquivos SUID com find e coleta metadados.

    Retorna (resultados, quantidade_de_erros_stat, aviso_do_find).
    """
    find_path = shutil.which("find")
    if not find_path:
        raise RuntimeError("O comando 'find' não foi encontrado. Instale o pacote findutils.")

    try:
        completed = subprocess.run(
            [find_path, root_path, "-type", "f", "-perm", "-4000", "-print0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Não foi possível executar o comando find: {exc}") from exc

    paths = [os.fsdecode(raw_path) for raw_path in completed.stdout.split(b"\0") if raw_path]
    results: list[dict[str, Any]] = []
    stat_errors = 0

    for path in paths:
        try:
            info = os.stat(path, follow_symlinks=False)
            # Confirma novamente o bit SUID para lidar com mudanças durante a varredura.
            if not stat.S_ISREG(info.st_mode) or not (info.st_mode & stat.S_ISUID):
                continue

            details = classify_file(path)
            results.append({
                "path": path,
                "permissions": stat.filemode(info.st_mode),
                "owner": owner_name(info.st_uid),
                "group": group_name(info.st_gid),
                "risk": details["risk"],
                "category": details["category"],
                "impact": details["impact"],
                "recommendation": details["recommendation"],
            })
        except (OSError, PermissionError):
            stat_errors += 1

    warning = None
    if completed.returncode != 0:
        warning = "O find terminou com avisos ou erros. Alguns diretórios podem não ter sido acessíveis."
    if completed.stderr:
        # Não despeja milhares de linhas do find no terminal; o aviso acima resume o caso.
        warning = warning or "O find informou avisos durante a varredura; confira as permissões de acesso."

    results.sort(key=lambda item: (item["risk"] not in ("CRÍTICO", "ALTO"), item["risk"], item["path"].lower()))
    return results, stat_errors, warning


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Localiza arquivos regulares com bit SUID e apresenta informações para auditoria defensiva.",
        epilog="Exemplo: python3 suid_scanner.py --path /usr/bin --json resultado.json",
    )
    parser.add_argument(
        "--path", default="/", metavar="DIRETÓRIO",
        help="Diretório inicial da varredura (padrão: /). A varredura em / pode demorar.",
    )
    parser.add_argument(
        "--json", dest="json_path", metavar="ARQUIVO",
        help="Salva os resultados em um arquivo JSON.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    return parser


def render_results(results: list[dict[str, Any]], stat_errors: int) -> None:
    table = Table(title="Arquivos SUID encontrados", show_lines=True, header_style="bold cyan")
    table.add_column("Caminho", style="cyan", overflow="fold")
    table.add_column("Permissões", justify="center", no_wrap=True)
    table.add_column("Proprietário:Grupo", overflow="fold")
    table.add_column("Risco potencial", justify="center", no_wrap=True)
    table.add_column("Categoria", overflow="fold")
    table.add_column("Impacto / observação", overflow="fold")
    table.add_column("Recomendação", overflow="fold")

    for item in results:
        risk = item["risk"]
        table.add_row(
            item["path"],
            item["permissions"],
            f'{item["owner"]}:{item["group"]}',
            f'[{RISK_STYLES.get(risk, "bold")}] {risk} [/{RISK_STYLES.get(risk, "bold")}]',
            item["category"],
            item["impact"],
            item["recommendation"],
        )

    console.print(table)
    counts: dict[str, int] = {}
    for item in results:
        counts[item["risk"]] = counts.get(item["risk"], 0) + 1

    summary = [f"Arquivos SUID encontrados: [bold]{len(results)}[/bold]"]
    for risk in ("CRÍTICO", "ALTO", "MÉDIO", "BAIXO", "REVISAR"):
        if counts.get(risk):
            style = RISK_STYLES.get(risk, "bold")
            summary.append(f"[{style}]{risk}: {counts[risk]}[/{style}]")
    if stat_errors:
        summary.append(f"Falhas ao consultar metadados: {stat_errors}")
    console.print(Panel("\n".join(summary), title="Resumo", expand=False))


def save_json(json_path: str, results: list[dict[str, Any]], root_path: str) -> None:
    output = {
        "tool": APP_NAME,
        "version": VERSION,
        "scan_path": root_path,
        "result_count": len(results),
        "results": results,
        "note": "Classificações são heurísticas e não confirmam vulnerabilidades.",
    }
    destination = Path(json_path).expanduser()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Não foi possível salvar o JSON em '{destination}': {exc}") from exc
    console.print(f"\n[green]Relatório JSON salvo em:[/green] {destination}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    root_path = os.path.abspath(os.path.expanduser(args.path))

    if not os.path.isdir(root_path):
        console.print(f"[bold red]Erro:[/bold red] o caminho não é um diretório válido: {root_path}")
        return 2

    console.print(Panel(
        f"[bold red]{APP_NAME} v{VERSION}[/bold red]\n"
        "[dim]Ferramenta educacional para auditoria de permissões SUID no Linux[/dim]\n"
        f"[dim]Diretório analisado: {root_path}[/dim]",
        expand=False,
    ))
    console.print("[dim]Iniciando varredura. Analisar '/' pode levar algum tempo...[/dim]\n")

    try:
        results, stat_errors, warning = scan_suid_files(root_path)
        render_results(results, stat_errors)
        if warning:
            console.print(f"\n[yellow]Aviso:[/yellow] {warning}")
        if args.json_path:
            save_json(args.json_path, results, root_path)
    except RuntimeError as exc:
        console.print(f"[bold red]Erro:[/bold red] {exc}")
        return 1
    except KeyboardInterrupt:
        console.print("\n[yellow]Varredura interrompida pelo usuário.[/yellow]")
        return 130

    console.print("\n[dim]Nota: o nível de risco é uma heurística baseada no nome do arquivo. Revise cada resultado manualmente.[/dim]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
