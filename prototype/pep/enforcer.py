"""
pep/enforcer.py — Policy Enforcement Point (PEP).

Public interface:
  enforcer.intercept(call, trace_state) -> (PolicyDecision, LabeledData | None)

Internal structure:
  evaluate()        — pure decision; no side effects on tools
  execute_allowed() — runs the tool and labels the result
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from datatypes import (
    DS, SI, LabeledData, PolicyDecision, ToolCall, TraceState,
)
from pep.capability_token import CapabilityToken
from pep.ds_detector import DSDetector
from pep.label_tracker import LabelTracker
from pep.path_normalizer import normalize_workspace_path
from pep.rules import RuleEngine
from audit.logger import AuditLogger


_HIGH_RISK_TOOLS = {
    "shell.run", "bash.run", "exec.run",
    "send_email.send", "http_post.post",
    "delete.delete", "rm.run",
}


# Filesystem-family tools whose `args["path"]` participates in R03.
# Path normalization runs pre-call for every entry in this set.
_FILESYSTEM_TOOLS = {
    "filesystem.read_file", "filesystem.write_file",
    "delete.delete", "rm.run", "drop_table.run", "truncate.run",
}


class PEPEnforcer:
    """
    Policy Enforcement Point.

    Baseline switching via LabelTracker.ifc_enabled and the skip_pep flag:
      skip_pep=True   → Baseline A (No Defense): no evaluation, execute directly
      ifc_enabled=False → Baseline C (Runtime Ablation): evaluate but no SI propagation
      ifc_enabled=True  → Baseline D (Full): full IFC + evaluation
    """

    def __init__(
        self,
        token: CapabilityToken,
        rule_engine: RuleEngine,
        label_tracker: LabelTracker,
        audit_logger: AuditLogger,
        tool_registry,           # tools.registry.ToolRegistry (injected)
        skip_pep: bool = False,  # True → Baseline A
        workspace_root: Optional[str] = None,  # JISA v8: path-norm anchor
        path_normalization_enabled: bool = True,  # set False for D0 ablation
    ):
        self._token = token
        self._rules = rule_engine
        self._tracker = label_tracker
        self._logger = audit_logger
        self._registry = tool_registry
        self._skip_pep = skip_pep
        self._ds = DSDetector()
        # JISA v8 path-norm config:
        #   workspace_root: absolute path of `workspace/` for membership tests.
        #     Defaults to <cwd>/workspace, matching the prototype's runtime layout.
        #   path_normalization_enabled: True for v8 D, False for the D0 ablation
        #     baseline (raw R03 prefix-match — preserves v7 behaviour).
        self._workspace_root = (
            Path(workspace_root) if workspace_root
            else Path.cwd() / "workspace"
        )
        self._path_normalization_enabled = path_normalization_enabled

    # ------------------------------------------------------------------
    # Main public interface
    # ------------------------------------------------------------------

    def intercept(
        self,
        call: ToolCall,
        trace_state: TraceState,
    ) -> tuple[PolicyDecision, Optional[LabeledData]]:
        """
        Intercept a tool call: evaluate policy, log audit event, optionally execute.

        Returns:
          (ALLOW decision,  LabeledData)  — tool was executed
          (DENY decision,   None)         — tool was blocked
          (CONFIRM decision, None)        — awaiting confirmation; caller decides
        """
        if self._skip_pep:
            # Baseline A: bypass all policy checks
            result = self.execute_allowed(call)
            # Still log for completeness (with ALLOW decision)
            allow = PolicyDecision(
                action="ALLOW",
                matched_rule=None,
                reason="No defense baseline — PEP bypassed",
                evaluated_si=trace_state.current_si,
                evaluated_ds=trace_state.current_ds,
            )
            self._logger.log(call, allow, trace_state)
            return allow, result

        decision = self.evaluate(call, trace_state)

        # Track high-risk call timestamps for R05 (regardless of decision)
        if call.tool in _HIGH_RISK_TOOLS:
            self._tracker.record_high_risk_call(call.trace_id)

        # Always write audit event
        self._logger.log(call, decision, trace_state)

        if decision.action == "ALLOW":
            result = self.execute_allowed(call)
            return decision, result

        # DENY or REQUIRE_CONFIRM: no execution
        self._tracker.advance_step(call.trace_id)
        return decision, None

    # ------------------------------------------------------------------
    # evaluate() — pure decision, no tool execution, no audit write
    # ------------------------------------------------------------------

    def evaluate(
        self,
        call: ToolCall,
        trace_state: TraceState,
    ) -> PolicyDecision:
        """
        Evaluate policy for a tool call.  Pure function: no side effects.

        Order of checks:
          0. Path normalization (filesystem tools only; option-b: pre-call)
          1. Capability Token: tool allowed?
          2. Capability Token: call limit not exceeded?
          3. DS detection on args
          4. Get current SI/DS from LabelTracker
          5. Rule engine R01–R05 (with normalized path)
        """
        # 0. JISA v8 path normalization. For filesystem tools we resolve the
        # agent-supplied path BEFORE R03 sees it, then attach the resolution
        # metadata to the resulting PolicyDecision so the audit log records
        # both raw_path (what the model said) and normalized_path (what R03
        # actually evaluated). See pep/path_normalizer.py for the algorithm.
        path_norm_meta: Optional[dict] = None
        rule_args = call.args
        if (
            self._path_normalization_enabled
            and call.tool in _FILESYSTEM_TOOLS
            and "path" in (call.args or {})
        ):
            np = normalize_workspace_path(
                call.args["path"],
                workspace_root=self._workspace_root,
            )
            path_norm_meta = np.to_audit_fields()
            # Substitute the policy_path into a copy of args for R03 evaluation.
            # We DO NOT mutate the original args — execute_allowed() needs the
            # raw path to drive the tool itself, since the tool's I/O is rooted
            # in the workspace_root and accepts the agent's literal path form.
            rule_args = dict(call.args)
            rule_args["path"] = np.policy_path

        def _attach(decision: PolicyDecision) -> PolicyDecision:
            """Attach path_norm metadata to a decision (no-op when None)."""
            if path_norm_meta is not None:
                decision.path_norm = path_norm_meta
            return decision

        # 1. Token: tool allowed?
        if not self._token.check_tool_allowed(call.tool):
            return _attach(PolicyDecision(
                action="DENY",
                matched_rule="TOKEN",
                reason=f"Tool '{call.tool}' not in capability token allow_tools",
                evaluated_si=trace_state.current_si,
                evaluated_ds=trace_state.current_ds,
            ))

        # 2. Token: call limit
        if not self._token.check_call_limit(call.tool):
            return _attach(PolicyDecision(
                action="DENY",
                matched_rule="TOKEN_LIMIT",
                reason=f"Call limit exceeded for '{call.tool}'",
                evaluated_si=trace_state.current_si,
                evaluated_ds=trace_state.current_ds,
            ))

        # 3. DS detection on args (merge into trace DS)
        args_ds = self._ds.detect(call.args)
        # Merge with trace DS (sticky: SENSITIVE wins)
        effective_ds = DS.merge(trace_state.current_ds, args_ds)

        # 4. Get effective SI/DS from LabelTracker
        #    (respects ifc_enabled flag for baseline C vs D)
        si, _ = self._tracker.get_labels_for_call(call.trace_id)
        ds = effective_ds

        # 5. Rule engine — R03 sees normalized path via rule_args
        return _attach(
            self._rules.evaluate(call.tool, si, ds, rule_args, trace_state)
        )

    # ------------------------------------------------------------------
    # execute_allowed() — run tool, label result, update tracker
    # ------------------------------------------------------------------

    def execute_allowed(self, call: ToolCall) -> LabeledData:
        """
        Execute a tool that has been ALLOW-ed.
        Labels the result with the server's SI and detects DS on content.
        Updates LabelTracker with the result's labels.
        Records the call in CapabilityToken counters.
        """
        # Execute
        raw_result: str = self._registry.execute(call)

        # Label result
        server_si = self._token.get_tool_si(call.tool)
        result_ds = self._ds.detect(raw_result)

        labeled = LabeledData(
            value=raw_result,
            si=server_si,
            ds=result_ds,
            source_tool=call.tool,
            trace_id=call.trace_id,
        )

        # Update tracker
        self._tracker.update_after_tool_return(call.trace_id, labeled)

        # Update token call counter
        self._token.record_call(call.tool)

        return labeled
