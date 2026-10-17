from recon_ai.phases import PHASES


def command(script, domain, threads, output, from_phase=None):
    cmd = [script, "--output", output]
    if from_phase:
        cmd.extend(["--from", from_phase])
    cmd.extend([domain, str(threads)])
    return cmd


def describe(domain, threads, tools, output, from_phase=None):
    lines = [
        f"alvo: {domain}",
        f"saida: {output}",
        f"threads_padrao: {threads}",
    ]
    for name, item in tools.items():
        if not isinstance(item, dict):
            continue
        enabled = item.get("enabled", True)
        parts = [f"ferramenta: {name}", f"enabled={str(enabled).lower()}"]
        if item.get("threads") is not None:
            parts.append(f"threads={item['threads']}")
        if item.get("rate_limit") is not None:
            parts.append(f"rate_limit={item['rate_limit']}")
        lines.append(" ".join(parts))
    start = from_phase or PHASES[0]
    lines.append("fases: " + " ".join(PHASES[PHASES.index(start) :]))
    lines.append("rede: nao")
    return "\n".join(lines)
