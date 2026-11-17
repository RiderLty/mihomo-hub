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
