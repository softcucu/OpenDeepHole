import { useEffect, useState } from "react";
import {
  listFeedback,
  updateFeedback,
  deleteFeedback,
  createFeedback,
  getSkillContent,
} from "../api/client";
import type { FeedbackEntry, CheckerInfo } from "../types";

interface Props {
  checkers: CheckerInfo[];
  /** Pre-select specific vuln_types as initial tabs (e.g. from scan_items). */
  initialTypes?: string[];
  /** Scan ID for SKILL preview. */
  scanId?: string;
  /** When provided, entries can be selected for SKILL inclusion. */
  selectedIds?: Set<string>;
  onSelectionChange?: (ids: Set<string>) => void;
  onFeedbackCreated?: (feedbackIds: string[]) => void | Promise<void>;
  /** project_id to associate when creating new entries from a scan. */
  projectId?: string;
  onClose: () => void;
}

export default function FeedbackManager({
  checkers,
  initialTypes,
  scanId,
  selectedIds,
  onSelectionChange,
  onFeedbackCreated,
  projectId,
  onClose,
}: Props) {
  const [entries, setEntries] = useState<FeedbackEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeType, setActiveType] = useState<string | null>(
    initialTypes?.[0] ?? null
  );
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editVerdict, setEditVerdict] = useState<string>("");
  const [editReason, setEditReason] = useState<string>("");
  const [editTicketSubmitted, setEditTicketSubmitted] = useState(false);
  const [editTicketId, setEditTicketId] = useState("");
  const [addMode, setAddMode] = useState(false);
  const [addForm, setAddForm] = useState({
    vuln_type: "",
    verdict: "false_positive" as string,
    file: "",
    line: 0,
    function: "",
    description: "",
    reason: "",
    ticket_submitted: false,
    ticket_id: "",
    function_source: "",
  });

  // SKILL preview state
  const [showSkill, setShowSkill] = useState(false);
  const [skillContent, setSkillContent] = useState<string>("");
  const [skillLoading, setSkillLoading] = useState(false);

  const selectable = !!selectedIds && !!onSelectionChange;
  const allTypes = checkers.map((c) => c.name);

  const refresh = async () => {
    setLoading(true);
    try {
      const data = await listFeedback(activeType || undefined);
      setEntries(data);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, [activeType]);

  // Load SKILL preview when tab changes or when requested
  const loadSkillPreview = async () => {
    if (!scanId || !activeType) return;
    setSkillLoading(true);
    try {
      const content = await getSkillContent(scanId, activeType);
      setSkillContent(content);
    } catch {
      setSkillContent("无法加载 SKILL 内容（扫描工作区可能不存在）");
    } finally {
      setSkillLoading(false);
    }
  };

  useEffect(() => {
    if (showSkill && scanId && activeType) {
      loadSkillPreview();
    }
  }, [showSkill, activeType, scanId]);

  // Group entries by vuln_type for tab counts
  const typeCounts: Record<string, number> = {};
  for (const e of entries) {
    typeCounts[e.vuln_type] = (typeCounts[e.vuln_type] || 0) + 1;
  }

  const handleToggleSelect = (id: string) => {
    if (!selectedIds || !onSelectionChange) return;
    const next = new Set(selectedIds);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onSelectionChange(next);
  };

  const handleSelectAll = () => {
    if (!onSelectionChange) return;
    // Merge with existing selections from other types
    const next = new Set(selectedIds);
    for (const e of entries) next.add(e.id);
    onSelectionChange(next);
  };

  const handleSelectNone = () => {
    if (!onSelectionChange || !selectedIds) return;
    // Only remove entries of the current type
    const currentTypeIds = new Set(entries.map((e) => e.id));
    const next = new Set(selectedIds);
    for (const id of currentTypeIds) next.delete(id);
    onSelectionChange(next);
  };

  const handleStartEdit = (entry: FeedbackEntry) => {
    setEditingId(entry.id);
    setEditVerdict(entry.verdict);
    setEditReason(entry.reason);
    setEditTicketSubmitted(entry.ticket_submitted);
    setEditTicketId(entry.ticket_id || "");
  };

  const handleSaveEdit = async () => {
    if (!editingId) return;
    try {
      const updated = await updateFeedback(editingId, {
        verdict: editVerdict,
        reason: editReason,
        ticket_submitted: editTicketSubmitted,
        ticket_id: editTicketSubmitted ? editTicketId : "",
      });
      setEntries((prev) => prev.map((e) => (e.id === editingId ? updated : e)));
      setEditingId(null);
    } catch {
      // ignore
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteFeedback(id);
      setEntries((prev) => prev.filter((e) => e.id !== id));
      if (selectedIds?.has(id) && onSelectionChange) {
        const next = new Set(selectedIds);
        next.delete(id);
        onSelectionChange(next);
      }
    } catch {
      // ignore
    }
  };

  const handleAdd = async () => {
    if (!addForm.vuln_type || !addForm.file || !addForm.function) return;
    try {
      const entry = await createFeedback({
        project_id: projectId || "",
        vuln_type: addForm.vuln_type,
        verdict: addForm.verdict,
        file: addForm.file,
        line: addForm.line,
        function: addForm.function,
        description: addForm.description,
        reason: addForm.reason,
        ticket_submitted: addForm.ticket_submitted,
        ticket_id: addForm.ticket_submitted ? addForm.ticket_id : "",
        function_source: addForm.function_source,
        source_scan_id: scanId,
      });
      setEntries((prev) => [entry, ...prev]);
      await onFeedbackCreated?.([entry.id]);
      setAddMode(false);
      setAddForm({
        vuln_type: activeType || "",
        verdict: "false_positive",
        file: "",
        line: 0,
        function: "",
        description: "",
        reason: "",
        ticket_submitted: false,
        ticket_id: "",
        function_source: "",
      });
    } catch {
      // ignore
    }
  };

  const selectedCount = selectedIds?.size || 0;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 z-40" onClick={onClose} />

      {/* Panel */}
      <div className="fixed right-0 top-0 bottom-0 w-[42rem] max-w-full bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              误报屏蔽规则
            </h3>
            {selectable && (
              <p className="text-xs text-slate-400 mt-0.5">
                已选 <span className="text-blue-400 font-semibold">{selectedCount}</span> 条规则用于 SKILL
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Type tabs */}
        <div className="flex items-center gap-1 px-5 py-3 border-b border-slate-700/50 overflow-x-auto">
          <button
            onClick={() => { setActiveType(null); setShowSkill(false); }}
            className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
              activeType === null
                ? "bg-slate-700 text-white"
                : "text-slate-400 hover:bg-slate-800"
            }`}
          >
            全部
          </button>
          {allTypes.map((t) => (
            <button
              key={t}
              onClick={() => setActiveType(t)}
              className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors flex items-center gap-1 ${
                activeType === t
                  ? "bg-slate-700 text-white"
                  : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              {t.toUpperCase()}
              {typeCounts[t] ? (
                <span className="text-slate-500">({typeCounts[t]})</span>
              ) : null}
            </button>
          ))}
        </div>

        {/* Actions bar */}
        <div className="flex items-center gap-2 px-5 py-2 border-b border-slate-700/30">
          <button
            onClick={() => {
              setAddMode(true);
              setAddForm((f) => ({ ...f, vuln_type: activeType || allTypes[0] || "" }));
            }}
            className="text-xs px-2.5 py-1 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 hover:bg-blue-500/20 transition-colors"
          >
            + 手动添加
          </button>
          {selectable && (
            <>
              <button
                onClick={handleSelectAll}
                className="text-xs px-2 py-1 text-slate-400 hover:text-slate-200 transition-colors"
              >
                全选当前类型
              </button>
              <button
                onClick={handleSelectNone}
                className="text-xs px-2 py-1 text-slate-400 hover:text-slate-200 transition-colors"
              >
                取消全选
              </button>
            </>
          )}
          {scanId && activeType && (
            <button
              onClick={() => setShowSkill(!showSkill)}
              className={`text-xs px-2.5 py-1 rounded transition-colors ${
                showSkill
                  ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                  : "text-slate-400 hover:text-slate-200 border border-slate-700 hover:border-slate-600"
              }`}
            >
              {showSkill ? "隐藏 SKILL" : "查看 SKILL"}
            </button>
          )}
          <button
            onClick={refresh}
            className="ml-auto text-xs px-2 py-1 text-slate-500 hover:text-slate-300 transition-colors"
          >
            刷新
          </button>
        </div>

        {/* SKILL preview */}
        {showSkill && (
          <div className="px-5 py-3 border-b border-slate-700/50 bg-slate-800/50 max-h-64 overflow-y-auto">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-semibold text-emerald-400 uppercase">
                当前 SKILL — {activeType?.toUpperCase()}
              </h4>
              <button
                onClick={loadSkillPreview}
                className="text-xs text-slate-500 hover:text-slate-300"
              >
                刷新预览
              </button>
            </div>
            {skillLoading ? (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <div className="w-3 h-3 border border-slate-600 border-t-blue-400 rounded-full animate-spin" />
                加载中...
              </div>
            ) : (
              <pre className="text-xs text-slate-400 whitespace-pre-wrap leading-relaxed font-mono">
                {skillContent}
              </pre>
            )}
          </div>
        )}

        {/* Add form */}
        {addMode && (
          <div className="px-5 py-3 border-b border-slate-700/50 bg-slate-800/50 space-y-2">
            <div className="flex gap-2">
              <select
                value={addForm.vuln_type}
                onChange={(e) => setAddForm((f) => ({ ...f, vuln_type: e.target.value }))}
                className="bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200"
              >
                {allTypes.map((t) => (
                  <option key={t} value={t}>{t.toUpperCase()}</option>
                ))}
              </select>
              <select
                value={addForm.verdict}
                onChange={(e) => setAddForm((f) => ({ ...f, verdict: e.target.value }))}
                className="bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200"
              >
                <option value="confirmed">确认正报</option>
                <option value="false_positive">实为误报</option>
              </select>
            </div>
            <div className="flex gap-2">
              <input
                value={addForm.file}
                onChange={(e) => setAddForm((f) => ({ ...f, file: e.target.value }))}
                placeholder="文件路径"
                className="flex-1 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
              />
              <input
                value={addForm.line || ""}
                onChange={(e) => setAddForm((f) => ({ ...f, line: parseInt(e.target.value) || 0 }))}
                placeholder="行号"
                type="number"
                className="w-20 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
              />
              <input
                value={addForm.function}
                onChange={(e) => setAddForm((f) => ({ ...f, function: e.target.value }))}
                placeholder="函数名"
                className="flex-1 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
              />
            </div>
            <input
              value={addForm.description}
              onChange={(e) => setAddForm((f) => ({ ...f, description: e.target.value }))}
              placeholder="描述"
              className="w-full bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
            />
            <input
              value={addForm.reason}
              onChange={(e) => setAddForm((f) => ({ ...f, reason: e.target.value }))}
              placeholder="理由"
              className="w-full bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
            />
            <div className="flex flex-wrap items-center gap-2">
              <label className="flex items-center gap-1.5 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={addForm.ticket_submitted}
                  onChange={(e) => setAddForm((f) => ({
                    ...f,
                    ticket_submitted: e.target.checked,
                    ticket_id: e.target.checked ? f.ticket_id : "",
                  }))}
                  className="h-3.5 w-3.5 rounded accent-blue-600"
                />
                已提单
              </label>
              {addForm.ticket_submitted && (
                <input
                  value={addForm.ticket_id}
                  onChange={(e) => setAddForm((f) => ({ ...f, ticket_id: e.target.value }))}
                  placeholder="问题单号"
                  className="min-w-[10rem] flex-1 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
                />
              )}
            </div>
            <textarea
              value={addForm.function_source}
              onChange={(e) => setAddForm((f) => ({ ...f, function_source: e.target.value }))}
              placeholder="函数源码（可选）"
              rows={5}
              className="w-full bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500 font-mono resize-y"
            />
            <div className="flex gap-2">
              <button
                onClick={handleAdd}
                className="px-3 py-1 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded transition-colors"
              >
                添加
              </button>
              <button
                onClick={() => setAddMode(false)}
                className="px-3 py-1 text-xs text-slate-400 hover:text-slate-300 transition-colors"
              >
                取消
              </button>
            </div>
          </div>
        )}

        {/* Entry list */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center h-32">
              <div className="w-5 h-5 border-2 border-slate-600 border-t-blue-400 rounded-full animate-spin" />
            </div>
          ) : entries.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-sm text-slate-500">
              暂无规则记录
            </div>
          ) : (
            <div className="divide-y divide-slate-700/50">
              {entries.map((entry) => (
                <FeedbackRow
                  key={entry.id}
                  entry={entry}
                  selectable={selectable}
                  selected={selectedIds?.has(entry.id) || false}
                  onToggleSelect={() => handleToggleSelect(entry.id)}
                  editing={editingId === entry.id}
                  editVerdict={editVerdict}
                  editReason={editReason}
                  editTicketSubmitted={editTicketSubmitted}
                  editTicketId={editTicketId}
                  onEditVerdictChange={setEditVerdict}
                  onEditReasonChange={setEditReason}
                  onEditTicketSubmittedChange={setEditTicketSubmitted}
                  onEditTicketIdChange={setEditTicketId}
                  onStartEdit={() => handleStartEdit(entry)}
                  onSaveEdit={handleSaveEdit}
                  onCancelEdit={() => setEditingId(null)}
                  onDelete={() => handleDelete(entry.id)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function FeedbackRow({
  entry,
  selectable,
  selected,
  onToggleSelect,
  editing,
  editVerdict,
  editReason,
  editTicketSubmitted,
  editTicketId,
  onEditVerdictChange,
  onEditReasonChange,
  onEditTicketSubmittedChange,
  onEditTicketIdChange,
  onStartEdit,
  onSaveEdit,
  onCancelEdit,
  onDelete,
}: {
  entry: FeedbackEntry;
  selectable: boolean;
  selected: boolean;
  onToggleSelect: () => void;
  editing: boolean;
  editVerdict: string;
  editReason: string;
  editTicketSubmitted: boolean;
  editTicketId: string;
  onEditVerdictChange: (v: string) => void;
  onEditReasonChange: (v: string) => void;
  onEditTicketSubmittedChange: (v: boolean) => void;
  onEditTicketIdChange: (v: string) => void;
  onStartEdit: () => void;
  onSaveEdit: () => void;
  onCancelEdit: () => void;
  onDelete: () => void;
}) {
  const [confirmDelete, setConfirmDelete] = useState(false);

  const verdictBadge = entry.verdict === "confirmed"
    ? "bg-red-500/20 text-red-400 border-red-500/30"
    : "bg-green-500/20 text-green-400 border-green-500/30";
  const verdictLabel = entry.verdict === "confirmed" ? "正报" : "误报";

  return (
    <div className={`px-5 py-3 hover:bg-slate-800/30 transition-colors ${selected ? "bg-blue-500/5" : ""}`}>
      <div className="flex items-start gap-3">
        {/* Selection checkbox */}
        {selectable && (
          <input
            type="checkbox"
            checked={selected}
            onChange={onToggleSelect}
            className="mt-1 w-3.5 h-3.5 rounded text-blue-600 accent-blue-600 shrink-0"
          />
        )}

        <div className="flex-1 min-w-0">
          {/* Header line */}
          <div className="flex flex-wrap items-center gap-2 mb-1">
            <span className={`text-xs font-semibold px-1.5 py-0.5 rounded border ${verdictBadge}`}>
              {verdictLabel}
            </span>
            <span className="text-xs font-semibold text-slate-400 bg-slate-700/50 px-1.5 py-0.5 rounded">
              {entry.vuln_type.toUpperCase()}
            </span>
            {entry.ticket_submitted && (
              <span
                className="text-xs font-semibold text-blue-300 bg-blue-500/10 border border-blue-500/30 px-1.5 py-0.5 rounded"
                title={entry.ticket_id || "已提单"}
              >
                {entry.ticket_id ? `已提单 ${entry.ticket_id}` : "已提单"}
              </span>
            )}
            <span className="text-xs font-mono text-slate-400 truncate">
              {entry.file}:{entry.line}
            </span>
            <code className="text-xs text-slate-500 truncate">{entry.function}</code>
          </div>

          {/* Description */}
          <p className="text-xs text-slate-400 mb-1 line-clamp-2">{entry.description}</p>

          {/* Editing mode */}
          {editing ? (
            <div className="flex flex-wrap items-center gap-2 mt-2">
              <select
                value={editVerdict}
                onChange={(e) => onEditVerdictChange(e.target.value)}
                className="bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200"
              >
                <option value="confirmed">确认正报</option>
                <option value="false_positive">实为误报</option>
              </select>
              <input
                value={editReason}
                onChange={(e) => onEditReasonChange(e.target.value)}
                placeholder="理由..."
                className="flex-1 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
                autoFocus
                onKeyDown={(e) => { if (e.key === "Enter") onSaveEdit(); }}
              />
              <label className="flex items-center gap-1.5 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={editTicketSubmitted}
                  onChange={(e) => {
                    onEditTicketSubmittedChange(e.target.checked);
                    if (!e.target.checked) onEditTicketIdChange("");
                  }}
                  className="h-3.5 w-3.5 rounded accent-blue-600"
                />
                已提单
              </label>
              {editTicketSubmitted && (
                <input
                  value={editTicketId}
                  onChange={(e) => onEditTicketIdChange(e.target.value)}
                  placeholder="问题单号"
                  className="w-32 bg-slate-700 border border-slate-600 rounded px-2 py-1 text-xs text-slate-200 placeholder-slate-500"
                  onKeyDown={(e) => { if (e.key === "Enter") onSaveEdit(); }}
                />
              )}
              <button
                onClick={onSaveEdit}
                className="px-2 py-1 text-xs font-medium text-white bg-blue-600 hover:bg-blue-700 rounded transition-colors"
              >
                保存
              </button>
              <button
                onClick={onCancelEdit}
                className="px-2 py-1 text-xs text-slate-400 hover:text-slate-300 transition-colors"
              >
                取消
              </button>
            </div>
          ) : (
            <>
              {entry.reason && (
                <p className="text-xs text-slate-500">
                  <span className="text-slate-600">理由：</span>{entry.reason}
                </p>
              )}
              {/* Action buttons */}
              <div className="flex items-center gap-3 mt-1.5">
                <button
                  onClick={onStartEdit}
                  className="text-xs text-slate-500 hover:text-blue-400 transition-colors"
                >
                  编辑
                </button>
                {confirmDelete ? (
                  <span className="flex items-center gap-1.5">
                    <span className="text-xs text-red-400">确认删除？</span>
                    <button
                      onClick={onDelete}
                      className="text-xs text-red-400 hover:text-red-300 font-medium transition-colors"
                    >
                      是
                    </button>
                    <button
                      onClick={() => setConfirmDelete(false)}
                      className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
                    >
                      否
                    </button>
                  </span>
                ) : (
                  <button
                    onClick={() => setConfirmDelete(true)}
                    className="text-xs text-slate-500 hover:text-red-400 transition-colors"
                  >
                    删除
                  </button>
                )}
                <span className="text-xs text-slate-600">
                  {new Date(entry.created_at).toLocaleDateString()}
                </span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
