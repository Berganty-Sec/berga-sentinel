"""Interface desktop enxuta; operações demoradas rodam fora da thread gráfica."""

import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from uuid import uuid4

from .client_log import append_client_log, client_log_path, write_client_summary
from .comparison import compare_audits, write_comparison_html
from .config import DEFAULT_CONFIG, SentinelConfig
from .history import AuditHistory
from .logging_config import configure_logging
from .output_layout import AuditOutputLayout
from .reporting import write_audit_json, write_html, write_inventory_csv, write_pdf
from .scanner import validate_scope
from .network_interface import NetworkInterface, detect_active_interface
from .pipeline import run_audit

LOG = logging.getLogger(__name__)

class AuditUI:
    def __init__(self, root: tk.Tk, output_dir: Path,
                 config: SentinelConfig = DEFAULT_CONFIG):
        self.root = root
        self.output_dir = output_dir
        self.config = config
        self.history = AuditHistory(output_dir / "history")
        self.events: queue.Queue = queue.Queue()
        self.running = False
        self.cancel_event: threading.Event | None = None
        self.audit_id = ""
        self.raw_log_path = output_dir / "berga-sentinel.log"
        self.customer_log_path = output_dir / "berga-sentinel-cliente.log"
        self.generated_paths = None
        self.output_layout = None
        self.network_profile: NetworkInterface | None = None
        self.interface_detection_error = ""
        try:
            self.network_profile = detect_active_interface()
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.interface_detection_error = str(exc)
            LOG.warning("Detecção automática de interface indisponível: %s", exc)
        self.root.title("Berga Sentinel | Berga CyberSec")
        self.root.geometry("820x600")
        self.root.minsize(700, 480)
        self._build()
        self.root.after(150, self._poll_events)

    def _build(self):
        frame = ttk.Frame(self.root, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="BERGA CYBERSEC", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Auditoria de Segurança de Rede", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(2, 12))
        ttk.Label(frame, text="Interface ativa detectada").pack(anchor="w")
        if self.network_profile:
            profile = self.network_profile
            profile_text = (f"{profile.name} · IPv4 {profile.ipv4}/{profile.prefix_length} · "
                            f"Gateway {profile.gateway} · Escopo {profile.scope}")
        else:
            profile_text = "Não detectada: " + self.interface_detection_error
        ttk.Label(frame, text=profile_text, wraplength=760).pack(anchor="w", pady=(3, 10))
        ttk.Label(frame, text=f"Escopo IPv4 autorizado (CIDR; limite de {self.config.scan.max_hosts} endereços):").pack(anchor="w")
        self.scope = tk.StringVar(value=self.network_profile.scope if self.network_profile else "")
        ttk.Entry(frame, textvariable=self.scope, width=28).pack(anchor="w", pady=(4, 10))
        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Confirmo que tenho autorização do responsável pela rede para auditar o escopo exibido.", variable=self.authorized).pack(anchor="w", pady=(0, 12))
        buttons = ttk.Frame(frame)
        buttons.pack(anchor="w")
        self.start_button = ttk.Button(buttons, text="Iniciar auditoria", command=self.start_audit)
        self.start_button.pack(side="left")
        self.cancel_button = ttk.Button(buttons, text="Cancelar", command=self.cancel_audit, state="disabled")
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.export_button = ttk.Button(buttons, text="Exportar novamente", command=self.export, state="disabled")
        self.export_button.pack(side="left", padx=8)
        self.status = tk.StringVar(value="Pronto. As sondas são somente de leitura.")
        ttk.Label(frame, textvariable=self.status).pack(anchor="w", pady=(12, 4))
        self.progress = ttk.Progressbar(frame, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(0, 10))
        ttk.Label(frame, text="Atividade e resultados", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.output = tk.Text(frame, height=18, wrap="word", state="disabled", font=("Consolas", 9))
        self.output.pack(fill="both", expand=True, pady=(5, 0))
        self.result = None

    def cancel_audit(self):
        """Request cooperative cancellation at the next host/probe boundary."""
        if self.running and self.cancel_event is not None:
            self.cancel_event.set()
            self.cancel_button.configure(state="disabled")
            self.status.set("Cancelamento solicitado; encerrando sondas em andamento...")
            self._write("Cancelamento solicitado; as conexões em andamento serão interrompidas por timeout.")

    def _write(self, text: str):
        self.output.configure(state="normal")
        self.output.insert("end", text + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def start_audit(self):
        if not self.authorized.get():
            messagebox.showwarning("Autorização necessária", "Confirme a autorização antes de iniciar.")
            return
        previous_auto_scope = self.network_profile.scope if self.network_profile else ""
        current_scope_text = self.scope.get().strip()
        try:
            refreshed_profile = detect_active_interface()
            self.network_profile = refreshed_profile
            self.interface_detection_error = ""
            if not current_scope_text or current_scope_text == previous_auto_scope:
                self.scope.set(refreshed_profile.scope)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.network_profile = None
            self.interface_detection_error = str(exc)
            if not current_scope_text or current_scope_text == previous_auto_scope:
                self.scope.set("")
            LOG.warning("Não foi possível atualizar a interface antes da auditoria: %s", exc)
        try:
            network = validate_scope(self.scope.get(), self.config.scan.max_hosts)
        except ValueError as exc:
            messagebox.showerror("Escopo inválido", str(exc))
            return
        if self.running:
            return
        profile_text = (f"\nInterface: {self.network_profile.name}\nIPv4: {self.network_profile.ipv4}/"
                        f"{self.network_profile.prefix_length}\nGateway: {self.network_profile.gateway}"
                        if self.network_profile and self.network_profile.scope == str(network) else "")
        if not messagebox.askyesno("Confirmar descoberta autorizada",
                f"O Berga Sentinel fará descoberta somente de leitura no escopo {network}.{profile_text}\n\n"
                "Confirma que este escopo pertence a uma rede cuja auditoria você está autorizado a executar?"):
            return
        self.running = True
        self.cancel_event = threading.Event()
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.progress.configure(value=0, maximum=network.num_addresses if network.num_addresses <= 2 else network.num_addresses - 2)
        self.audit_id = uuid4().hex[:12]
        self.output_layout = AuditOutputLayout.create(self.output_dir, self.audit_id)
        self.raw_log_path = configure_logging(self.output_layout.directory, self.audit_id,
                                              self.config.log_level)
        self.customer_log_path = client_log_path(self.output_layout.directory, self.audit_id)
        append_client_log(self.customer_log_path, f"Auditoria {self.audit_id} iniciada | Escopo autorizado: {network}")
        self._write(f"Iniciando auditoria somente de leitura para {network}.")
        self._write(f"Todos os arquivos desta auditoria: {self.output_layout.directory}")
        LOG.info("Autorização confirmada na interface; auditoria=%s; escopo=%s", self.audit_id, network)
        self._write("BERGA SENTINEL — NETWORK DISCOVERY")
        if self.network_profile and self.network_profile.scope == str(network):
            self._write(f"Interface: {self.network_profile.name} | IPv4: {self.network_profile.ipv4}/{self.network_profile.prefix_length} | Gateway: {self.network_profile.gateway}")
            self._write("[OK] Interface detectada automaticamente")
        else:
            self._write("Interface: não associada ao escopo manual informado")
        self._write(f"Escopo autorizado: {network}")
        self._write("Métodos em camadas: ARP (cache local) → ICMP → TCP")
        threading.Thread(target=self._run_audit, args=(str(network), self.audit_id,
                                                       self.output_layout, self.cancel_event),
                         daemon=True, name="sentinel-audit").start()

    def _write_reports(self, result, layout: AuditOutputLayout):
        paths = []
        for profile in self.config.reports.profiles:
            name = {"developer": "tecnico", "analyst": "operacional", "client": "cliente"}[profile]
            if "html" in self.config.reports.formats:
                paths.append(write_html(result, layout.directory / f"relatorio-{name}.html", profile))
            if "pdf" in self.config.reports.formats:
                paths.append(write_pdf(result, layout.directory / f"relatorio-{name}.pdf", profile))
        if "json" in self.config.reports.formats:
            paths.append(write_audit_json(result, layout.directory / "auditoria-completa.json"))
        if "csv" in self.config.reports.formats:
            profiles = self.config.reports.profiles
            if "developer" in profiles or "analyst" in profiles:
                paths.append(write_inventory_csv(result, layout.directory / "inventario-detalhado.csv", "developer"))
            if "client" in profiles:
                paths.append(write_inventory_csv(result, layout.directory / "inventario-cliente.csv", "client"))
        return tuple(paths)

    def _run_audit(self, scope: str, audit_id: str, layout: AuditOutputLayout,
                   cancel_event: threading.Event | None = None):
        try:
            def progress(done, total, ip):
                self.events.put(("progress", done, total, ip))
            def on_stage(name):
                self.events.put(("stage", name, None, None))
            profile = self.network_profile if self.network_profile and self.network_profile.scope == scope else None
            result = run_audit(scope, progress, on_stage, audit_id, profile,
                               self.config, cancel_event)
            self.events.put(("stage", "Relatório", None, None))
            try:
                previous = self.history.latest(exclude_audit_id=audit_id, scope=result.scope)
                try:
                    self.history.save(result)
                except (OSError, ValueError) as history_error:
                    LOG.exception("Não foi possível salvar snapshot no histórico local")
                    self.events.put(("stage", f"Histórico indisponível: {history_error}", None, None))
                paths = list(self._write_reports(result, layout))
                if previous is not None:
                    comparison = compare_audits(previous, result)
                    paths.append(write_comparison_html(comparison,
                                                       layout.directory / "comparacao-anterior.html"))
                LOG.info("Relatórios e inventário gerados: %s", paths)
                self.events.put(("complete", result, tuple(paths), None))
            except Exception as report_error:
                LOG.exception("Auditoria concluída, mas falhou a geração do relatório")
                self.events.put(("complete", result, None, str(report_error)))
        except Exception as exc:
            LOG.exception("Falha na auditoria")
            self.events.put(("error", str(exc), None, None))

    def _poll_events(self):
        try:
            while True:
                kind, first, second, third = self.events.get_nowait()
                if kind == "progress":
                    self.progress.configure(value=first)
                    self.status.set(f"Verificados {first}/{second} endereços · último: {third}")
                elif kind == "stage":
                    self.status.set(f"Etapa atual: {first}")
                    self._write(f"Etapa: {first}")
                    if first == "Relatório":
                        self.cancel_button.configure(state="disabled")
                elif kind == "complete":
                    self.result = first
                    self.generated_paths = second
                    write_client_summary(self.result, self.customer_log_path)
                    self.running = False
                    self.start_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    self.export_button.configure(state="normal")
                    active_devices = [device for device in self.result.devices if device.is_active]
                    local_only = len(active_devices) == 1 and active_devices[0].is_local
                    outcome = ("Somente o host local foi identificado." if local_only else
                               f"Hosts ativos confirmados: {len(active_devices)}; entradas ARP sem confirmação: {len(self.result.devices) - len(active_devices)}.")
                    ending = "cancelada parcialmente" if self.result.cancelled else "concluída"
                    self.status.set(f"Descoberta {ending}: {len(active_devices)} hosts ativos confirmados; {len(self.result.devices) - len(active_devices)} entradas sem confirmação.")
                    self._write("BERGA SENTINEL — NETWORK DISCOVERY")
                    self._write(f"Escopo: {self.result.scope}")
                    self._write(outcome)
                    snapshot_counts = getattr(self.result, "discovery_method_counts", {})
                    if snapshot_counts:
                        self._write("Métodos: " + " · ".join(f"{name}: {count}" for name, count in snapshot_counts.items()))
                    timeout_counts = getattr(self.result, "discovery_timeout_counts", {})
                    if timeout_counts:
                        self._write("Timeouts: " + " · ".join(f"{name}: {count}" for name, count in timeout_counts.items()))
                    if self.result.discovery_errors:
                        self._write("Erros de descoberta: " + " · ".join(self.result.discovery_errors))
                    for device in self.result.devices:
                        local_label = "LOCAL HOST" if device.is_local else device.role
                        methods = ", ".join(device.discovered_by) or "Método não registrado"
                        self._write(f"{device.ip} | {local_label} | {device.presence_status} | {device.hostname} | métodos: {methods} | SO provável: {device.operating_system} | Portas: {', '.join(map(str, device.open_ports)) or 'nenhuma da lista'}")
                    self._write(f"Log técnico: {self.raw_log_path}")
                    self._write(f"Log para o cliente: {self.customer_log_path}")
                    if self.generated_paths:
                        append_client_log(self.customer_log_path, "Relatórios técnico, operacional e simplificado, JSON e inventários foram gerados na pasta desta auditoria.")
                        for artifact in self.generated_paths:
                            self._write(f"Relatório: {artifact}")
                    elif third:
                        self.status.set("Auditoria concluída; houve falha ao gerar os relatórios.")
                        self._write("Falha na geração dos relatórios: " + third)
                elif kind == "error":
                    self.running = False
                    self.start_button.configure(state="normal")
                    self.cancel_button.configure(state="disabled")
                    self.status.set("Falha na auditoria.")
                    append_client_log(self.customer_log_path, f"Auditoria {self.audit_id} interrompida por erro; consulte o log técnico para detalhes.")
                    self._write("Falha: " + first)
                    messagebox.showerror("Falha na auditoria", first)
        except queue.Empty:
            pass
        self.root.after(150, self._poll_events)

    def export(self):
        if not self.result or not self.output_layout:
            return
        try:
            self.generated_paths = self._write_reports(self.result, self.output_layout)
            LOG.info("Relatórios por perfil exportados: %s", self.generated_paths)
            append_client_log(self.customer_log_path, "Relatórios atualizados na pasta desta auditoria.")
            self.status.set("Etapa concluída: Relatório")
            self._write("Etapa: Relatório")
            for artifact in self.generated_paths:
                self._write(f"Relatório: {artifact}")
            messagebox.showinfo("Exportação concluída", f"Relatórios completos, operacionais e simplificados atualizados em:\n{self.output_layout.directory}")
        except Exception as exc:
            LOG.exception("Falha na exportação de relatórios")
            messagebox.showerror("Falha na exportação", str(exc))
