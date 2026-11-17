// 复制到剪贴板
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  e.preventDefault();
  const sel = btn.getAttribute('data-copy');
  const el = sel === 'self' ? btn : document.querySelector(sel);
  if (!el) return;
  const text = el.value !== undefined ? el.value : el.textContent;
  try {
    await navigator.clipboard.writeText(text.trim());
    const old = btn.textContent;
    btn.textContent = '已复制';
    setTimeout(() => { btn.textContent = old; }, 1200);
  } catch (err) {
    alert('复制失败：' + err);
  }
});

// 一键把文本内容填入输入框（例如把自动检测到的地址填进设置项）
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-fill]');
  if (!btn) return;
  e.preventDefault();
  const target = document.querySelector(btn.getAttribute('data-fill'));
  const source = document.querySelector(btn.getAttribute('data-value'));
  if (!target || !source) return;
  target.value = (source.textContent || '').trim();
  target.focus();
});

// 后端连通性检测
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-check-backend]');
  if (!btn) return;
  e.preventDefault();
  btn.disabled = true;
  btn.textContent = '检测中…';
  try {
    const resp = await fetch(`/backends/${btn.getAttribute('data-check-backend')}/check`, { method: 'POST' });
    const data = await resp.json();
    btn.textContent = data.ok ? '可达' : '不可达';
  } catch (err) {
    btn.textContent = '检测失败';
  }
  setTimeout(() => location.reload(), 700);
});

// 全部后端检测
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-check-all-backends]');
  if (!btn) return;
  e.preventDefault();
  btn.disabled = true;
  btn.textContent = '检测中…';
  try {
    await fetch('/backends/check-all', { method: 'POST' });
  } catch (err) {
    // 即使请求失败也刷新，页面会显示上次结果
  }
  setTimeout(() => location.reload(), 500);
});

// rule-provider URL 检测
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-check-providers]');
  if (!btn) return;
  e.preventDefault();
  const target = document.querySelector(btn.getAttribute('data-check-target'));
  const id = btn.getAttribute('data-check-providers');
  btn.disabled = true;
  if (target) target.textContent = '检测中…';
  try {
    const resp = await fetch(`/fronts/${id}/check-providers`, { method: 'POST' });
    const data = await resp.json();
    if (!target) return;
    if (data.error) {
      target.textContent = '错误：' + data.error;
    } else if (!data.results || !data.results.length) {
      target.textContent = '没有 rule-providers';
    } else {
      target.textContent = data.results.map((r) => {
        const mark = r.ok ? '✓' : '✗';
        const extra = [r.status ? String(r.status) : '', r.error || '', r.cached ? '(cached)' : '']
          .filter(Boolean).join(' ');
        return `${mark} ${r.name}  ${extra}`.trim();
      }).join('\n');
    }
  } catch (err) {
    if (target) target.textContent = '请求失败：' + err;
  } finally {
    btn.disabled = false;
  }
});

// 危险操作二次确认（按钮级，配合 formaction 使用）
document.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-confirm]');
  if (!btn) return;
  if (!confirm(btn.getAttribute('data-confirm'))) {
    e.preventDefault();
    e.stopPropagation();
  }
});

// 危险操作二次确认
document.addEventListener('submit', (e) => {
  const form = e.target;
  const msg = form.getAttribute('data-confirm');
  if (msg && !confirm(msg)) {
    e.preventDefault();
  }
});
