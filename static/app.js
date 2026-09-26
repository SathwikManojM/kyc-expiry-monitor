document.addEventListener('DOMContentLoaded', () => {
  const modal = document.querySelector('[data-modal]');
  const openButton = document.querySelector('[data-open-modal]');
  const closeButtons = document.querySelectorAll('[data-close-modal]');
  const closeModal = () => {
    if (modal) modal.hidden = true;
    document.body.classList.remove('modal-open');
  };
  openButton?.addEventListener('click', () => {
    if (!modal) return;
    modal.hidden = false;
    document.body.classList.add('modal-open');
    modal.querySelector('input')?.focus();
  });
  closeButtons.forEach(button => button.addEventListener('click', closeModal));
  modal?.addEventListener('click', event => {
    if (event.target === modal) closeModal();
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape') closeModal();
  });
  document.querySelectorAll('.flash-close').forEach(button => {
    button.addEventListener('click', () => button.closest('.flash')?.remove());
  });
});
