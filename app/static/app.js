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

// 危险操作二次确认
document.addEventListener('submit', (e) => {
  const form = e.target;
  const msg = form.getAttribute('data-confirm');
  if (msg && !confirm(msg)) {
    e.preventDefault();
  }
});
